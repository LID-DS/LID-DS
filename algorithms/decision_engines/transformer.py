import math
from enum import Enum
from functools import cache

import torch
from torch import nn
from torch.nn import functional as F
from torch.utils.data import Dataset, DataLoader
from torch.utils.tensorboard import SummaryWriter
from tqdm import tqdm

from algorithms.building_block import BuildingBlock
from algorithms.decision_engines.nn.transformer import CustomTransformer
from algorithms.features.impl.int_embedding import IntEmbeddingConcat
from algorithms.persistance import ModelCheckPoint
from dataloader.syscall import Syscall


class AnomalyScore(Enum):
    PRODUCT = 0
    MEAN = 1
    LAST = 2
    LOSS = 3

    def __str__(self):
        return str(self.name)

    def __repr__(self):
        return self.__str__()

    @staticmethod
    def argparse(s):
        try:
            return AnomalyScore[s.upper()]
        except KeyError:
            return s


class Transformer(BuildingBlock):
    """ Decision engine based on the Transformer architecture."""
    VERSION = "00.20"

    def __init__(
            self,
            input_vector: BuildingBlock,
            concat_int_embedding: IntEmbeddingConcat,
            epochs: int,
            batch_size: int,
            anomaly_scoring: AnomalyScore,
            checkpoint: ModelCheckPoint,
            num_heads: int,
            layers: int,
            model_dim: int,
            dropout: float,
            feedforward_dim: int,
            pre_layer_norm: bool,
            dedup_train_set: bool,
            learning_rate: float,
            retrain=False,
            log_grads=False):
        super().__init__()
        self._input_vector = input_vector
        self._concat_int_embedding = concat_int_embedding
        self._dependency_list = [input_vector]
        self._epochs = epochs
        self._batch_size = batch_size
        self._anomaly_scoring = anomaly_scoring
        self._checkpoint = checkpoint
        self._num_heads = num_heads
        self._layers = layers
        self._model_dim = model_dim
        self._dropout = dropout
        self._feedforward_dim = feedforward_dim
        self._pre_layer_norm = pre_layer_norm
        self._retrain = retrain
        self._dedup_train_set = dedup_train_set
        self._learning_rate = learning_rate
        self._loss_fn = F.cross_entropy
        self._optimizer = None
        self._anomaly_scores = {_: {} for _ in AnomalyScore}
        self._log_grads = log_grads

        self.train_losses = {}
        self.val_losses = {}
        self._training_set = []
        self._validation_set = []

        self.train_set_size = 0
        self.val_set_size = 0

        self._writer = SummaryWriter(log_dir=checkpoint.epochs_dir + "/tensorboard")
        self._device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

    def _init_model(self):
        num_tokens = len(self._concat_int_embedding)
        self.update_config_value("distinct_tokens", num_tokens)
        self._distinct_tokens = num_tokens
        self.transformer = TransformerModel(
            num_tokens,
            self._model_dim,
            self._num_heads,
            self._layers,
            self._dropout,
            self._feedforward_dim,
            pre_layer_norm=self._pre_layer_norm,
        ).to(self._device)

        n_params = sum(p.numel() for p in self.transformer.parameters())
        print("Transformer: number of parameters: %.2fT" % (n_params / 1e3,))
        self.update_config_value("n_params", n_params)

    def train_on(self, syscall: Syscall):
        input_vector: tuple = self._input_vector.get_result(syscall)
        if input_vector is not None:
            self._training_set.append(input_vector)

    def val_on(self, syscall: Syscall):
        input_vector: tuple = self._input_vector.get_result(syscall)
        if input_vector is not None:
            self._validation_set.append(input_vector)

    def fit(self):
        self._init_model()

        self._optimizer = torch.optim.Adam(
            self.transformer.parameters(),
            lr=self._learning_rate,
            betas=(0.9, 0.98),
            eps=1e-9
        )

        t_dataset = TransformerDataset(
            self._training_set,
            self._dedup_train_set,
            self._device
        )
        self.train_set_size = len(t_dataset)
        t_dataset_val = TransformerDataset(
            self._validation_set,
            self._dedup_train_set,
            self._device
        )
        self.val_set_size = len(t_dataset_val)

        train_dataloader = DataLoader(t_dataset, batch_size=self._batch_size, shuffle=True)
        val_dataloader = DataLoader(t_dataset_val, batch_size=self._batch_size, shuffle=True)

        last_epoch = 0
        if not self._retrain:
            last_epoch, self.train_losses, self.val_losses, _ = self._checkpoint.load(
                self.transformer,
                self._optimizer,
                self._epochs
            )
        for epoch in tqdm(range(last_epoch + 1, self._epochs + 1), "train&val".rjust(27), unit=" epoch"):
            # Training
            self.transformer.train()
            train_loss = 0
            for batch in train_dataloader:
                loss = self._forward_and_get_loss(batch)
                self._optimizer.zero_grad()
                loss.backward()
                self._optimizer.step()
                train_loss += loss.item()
            self.train_losses[epoch] = train_loss / len(train_dataloader)

            self.log_grads(epoch)

            # Validation
            self.transformer.eval()
            val_loss = 0
            with torch.no_grad():
                for batch in val_dataloader:
                    loss = self._forward_and_get_loss(batch)
                    val_loss += loss.item()
            self.val_losses[epoch] = val_loss / len(val_dataloader)

            if self._checkpoint and epoch % 5 - 1 == 0:
                self.save_epoch(epoch)
        # evaluation only on cpu
        self.transformer.eval()
        self._device = torch.device('cpu')
        self.transformer.to(self._device)

    def _forward_and_get_loss(self, batch):
        X, Y = batch
        sequence_length = X.size(1)
        mask = self.transformer.get_mask(sequence_length).to(self._device)
        pred = self.transformer(X, mask)
        # Permute pred to have batch size first again
        pred = pred.permute(1, 2, 0)
        # prediction probability for every possible syscall
        loss = self._loss_fn(pred, Y)
        return loss

    def log_grads(self, epoch):
        if not self._log_grads:
            return
        # logging weights and gradients
        for name, param in self.transformer.named_parameters():
            if param.requires_grad and param.grad is not None:
                self._writer.add_histogram(name, param, epoch)
                self._writer.add_scalar(name + '_mean', param.mean(), epoch)
                self._writer.add_scalar(name + '_std', param.std(), epoch)
                self._writer.add_histogram(name + '_grad', param.grad, epoch)
                self._writer.add_scalar(name + '_grad_mean', param.grad.mean(), epoch)
                self._writer.add_scalar(name + '_grad_std', param.grad.std(), epoch)

    def _calculate(self, syscall: Syscall):
        input_vector = self._input_vector.get_result(syscall)
        return self._cached_results(input_vector)

    @cache
    def _cached_results(self, input_vector):
        if input_vector is None:
            return None
        with torch.no_grad():
            X = torch.tensor([list(input_vector[:-1])], dtype=torch.long).to(device=self._device)
            Y = torch.tensor([list(input_vector[1:])], dtype=torch.long).to(device=self._device)

            mask = self.transformer.get_mask(X.size(1)).to(self._device)
            pred = self.transformer(X, mask)
            predicted_probs = nn.Softmax(dim=2)(pred).squeeze(1)

            if self._anomaly_scoring == AnomalyScore.PRODUCT:
                conditional_prob = predicted_probs[range(predicted_probs.shape[0]), input_vector[1:]].prod()
            elif self._anomaly_scoring == AnomalyScore.MEAN:
                conditional_prob = predicted_probs[range(predicted_probs.shape[0]), input_vector[1:]].mean()
            elif self._anomaly_scoring == AnomalyScore.LAST:
                conditional_prob = predicted_probs[predicted_probs.shape[0] - 1, input_vector[-1]]
            elif self._anomaly_scoring == AnomalyScore.LOSS:
                pred = pred.permute(1, 2, 0)
                return self._loss_fn(pred, Y).item()
            else:
                raise NotImplementedError(f"Anomaly scoring strategy not implemented for {self._anomaly_scoring}")

        return 1 - float(conditional_prob)

    def load_epoch(self, epoch):
        last_epoch, self.train_losses, self.val_losses, checkpoint = self._checkpoint.load(
            self.transformer,
            self._optimizer,
            epoch
        )
        if checkpoint:
            self._anomaly_scores = checkpoint.get("anomaly_scores", self._anomaly_scores)
        self.transformer.eval()
        self._device = torch.device('cpu')

    def save_epoch(self, epoch):
        self._checkpoint.save(
            self.transformer,
            self._optimizer,
            epoch,
            self.train_losses,
            self.val_losses,
            anomaly_scores=self._anomaly_scores
        )

    def get_cached_scores(self):
        return self._anomaly_scores[self._anomaly_scoring]

    def batched_results(self, input_vectors, batch_size=4096):
        self._device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.transformer.to(self._device)
        input_dataset = TransformerDataset(
            input_vectors,
            dedup_train_set=False,
            device=self._device
        )
        input_loader = DataLoader(input_dataset, batch_size=batch_size, shuffle=False)
        results = []
        for batch in input_loader:
            X, Y = batch
            sequence_length = X.size(1)
            mask = self.transformer.get_mask(sequence_length).to(self._device)
            pred = self.transformer(X, mask)
            pred = pred.permute(1, 2, 0)
            losses = self._loss_fn(pred, Y, reduction="none")

            predicted_probs = nn.Softmax(dim=1)(pred)  # (batch_size, vocab_size, seq_len)
            if self._anomaly_scoring == AnomalyScore.LAST:
                anomaly_scores = predicted_probs[range(predicted_probs.shape[0]), Y[:, -1], -1].tolist()
            elif self._anomaly_scoring == AnomalyScore.LOSS:
                anomaly_scores = losses.mean(dim=1).tolist()
            else:
                raise NotImplementedError(f"Anomaly scoring strategy not implemented for {self._anomaly_scoring}")
            results.extend(anomaly_scores)
        results = {vec: score for vec, score in zip(input_vectors, results)}
        self._anomaly_scores[self._anomaly_scoring] |= results
        return results

    def depends_on(self) -> list:
        return self._dependency_list


class TransformerDataset(Dataset):

    def __init__(self, IN, dedup_train_set, device):
        if dedup_train_set:
            IN = list(set(IN))
        IN = torch.tensor(IN, dtype=torch.long, device=device)
        self.X = IN[:, :-1]
        self.Y = IN[:, 1:]

    def __len__(self):
        return len(self.X)

    def __getitem__(self, index):
        return self.X[index], self.Y[index]


class TransformerModel(nn.Module):
    """
    Model from "A detailed guide to Pytorch's nn.Transformer() module.", by
    Daniel Melchor: https://medium.com/@danielmelchor/a-detailed-guide-to-pytorchs-nn-transformer-module-c80afbc9ffb1
    """

    def __init__(
            self,
            num_tokens,
            dim_model,
            num_heads,
            num_encoder_layers,
            dropout,
            feedforward_dim,
            pre_layer_norm):
        super().__init__()

        # INFO
        self.model_type = "Transformer"
        self.dim_model = dim_model

        # LAYERS
        self.positional_encoder = PositionalEncoding(dim_model=dim_model, dropout_p=dropout, max_len=5000)
        self.embedding = nn.Embedding(num_tokens, dim_model)

        self.transformer = CustomTransformer(
            d_model=dim_model,
            nhead=num_heads,
            num_encoder_layers=num_encoder_layers,
            dropout=dropout,
            dim_feedforward=feedforward_dim,
            pre_layer_norm=pre_layer_norm,
        )

        self.out = nn.Linear(dim_model, num_tokens)

    def forward(self, src, src_mask=None, src_pad_mask=None):
        # Src size must be (batch_size, src sequence length)

        # Embedding + positional encoding - Out size = (batch_size, sequence length, dim_model)
        src = self.embedding(src) * math.sqrt(self.dim_model)
        src = self.positional_encoder(src)

        # We could use the parameter batch_first=True, but our KDL version doesn't support it yet, so we permute
        # to obtain size (sequence length, batch_size, dim_model),
        src = src.permute(1, 0, 2)

        # Transformer blocks - Out size = (sequence length, batch_size, num_tokens)
        transformer_out = self.transformer(
            src,
            src_mask=src_mask,
            src_key_padding_mask=src_pad_mask,
        )
        out = self.out(transformer_out)

        return out

    @staticmethod
    def get_mask(size) -> torch.tensor:
        # Generates a square matrix where each row allows one word more to be seen
        mask = torch.tril(torch.ones(size, size) == 1)  # Lower triangular matrix
        mask = mask.float()
        mask = mask.masked_fill(mask == 0, float('-inf'))  # Convert zeros to -inf
        mask = mask.masked_fill(mask == 1, float(0.0))  # Convert ones to 0

        # EX for size=5:
        # [[0., -inf, -inf, -inf, -inf],
        #  [0.,   0., -inf, -inf, -inf],
        #  [0.,   0.,   0., -inf, -inf],
        #  [0.,   0.,   0.,   0., -inf],
        #  [0.,   0.,   0.,   0.,   0.]]

        return mask

    @staticmethod
    def create_pad_mask(matrix: torch.tensor, pad_token: int) -> torch.tensor:
        # If matrix = [1,2,3,0,0,0] where pad_token=0, the result mask is
        # [False, False, False, True, True, True]
        return matrix == pad_token


class PositionalEncoding(nn.Module):

    def __init__(self, dim_model, dropout_p, max_len):
        super().__init__()
        # Modified version from: https://pytorch.org/tutorials/beginner/transformer_tutorial.html
        # max_len determines how far the position can have an effect on a token (window)

        self.dropout = nn.Dropout(dropout_p)

        # Encoding - From formula
        pos_encoding = torch.zeros(max_len, dim_model)
        positions_list = torch.arange(0, max_len, dtype=torch.float).view(-1, 1)  # 0, 1, 2, 3, 4, 5
        division_term = torch.exp(
            torch.arange(0, dim_model, 2).float() * (-math.log(10000.0)) / dim_model
        )  # 1000^(2i/dim_model)

        # PE(pos, 2i) = sin(pos/1000^(2i/dim_model))
        pos_encoding[:, 0::2] = torch.sin(positions_list * division_term)

        # PE(pos, 2i + 1) = cos(pos/1000^(2i/dim_model))
        pos_encoding[:, 1::2] = torch.cos(positions_list * division_term)

        # Saving buffer (same as parameter without gradients needed)
        pos_encoding = pos_encoding.unsqueeze(0).transpose(0, 1)
        self.register_buffer("pos_encoding", pos_encoding)

    def forward(self, token_embedding: torch.tensor) -> torch.tensor:
        # Residual connection + pos encoding
        return self.dropout(token_embedding + self.pos_encoding[:token_embedding.size(0), :])
