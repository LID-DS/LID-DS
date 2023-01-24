import json
from pathlib import Path
from statistics import median

import sentencepiece as spm

from algorithms.building_block import BuildingBlock
from algorithms.persistance import load_from_json
from dataloader.syscall import Syscall


class SubWordUnitsTokenizer(BuildingBlock):
    """
        Tokenize a string into subword units.
        This is a wrapper around the SentencePiece library https://github.com/google/sentencepiece.
    """

    def __init__(self,
                 feature: BuildingBlock,
                 model_path_prefix: str,
                 vocab_size: int = 200,
                 max_pieces_length: int = 5,
                 use_padding: bool = True):
        """
        Args:
            feature: input building block, should return a string
            model_path_prefix: path to save model
            vocab_size: number of subword units, this is not a hard limit. The model will create fewer units if possible.
            max_pieces_length: maximum number of subword units to represent a feature (sentence/string).
            use_padding: if true, the feature will be padded to max_pieces_length.
        """
        super().__init__()
        self._dependency_list = [feature]
        self._feature = feature
        self._model_type = "bpe"
        self._model_path_prefix = f"{model_path_prefix}{self._model_type}_{vocab_size}"
        self._txt_path = f"{model_path_prefix}{self._model_type}.txt"
        self._vocab_size = vocab_size
        self._use_padding = use_padding
        self._pieces_length = max_pieces_length

        self._training_data: list[str] = []

        Path(self._model_path_prefix).parent.mkdir(parents=True, exist_ok=True)

        self._model = None

        if Path(self._model_path_prefix + ".model").exists():
            self._init_model()
            self._load_config()
            setattr(self, "train_on", super().train_on)
        elif Path(self._txt_path).exists():
            with open(self._txt_path) as f:
                self._training_data = f.read().splitlines()
            setattr(self, "train_on", super().train_on)

    def _init_model(self):
        if self._model is None:
            self._model = spm.SentencePieceProcessor()
            self._model.Load(self._model_path_prefix + ".model")
            self._vocab_size = self._model.GetPieceSize()

    def train_on(self, syscall: Syscall):
        result = self._feature.get_result(syscall)
        if result is not None:
            self._training_data.append(result)

    def _load_config(self):
        config = load_from_json(self._model_path_prefix + ".json")
        self._pieces_length = config["pieces_length"]

    def _save_config(self):
        config = {"pieces_length": self._pieces_length}
        with open(self._model_path_prefix + ".json", "w") as f:
            json.dump(config, f)

    def fit(self):
        if len(self._training_data) > 0:
            train_data = "\n".join(self._training_data)
            with open(self._txt_path, "w") as f:
                f.write(train_data)
            if not Path(self._model_path_prefix + ".model").exists():
                self._train_model()
            self._init_model()
            self._save_config()
            train_data_pieces = set([tuple(self._to_pieces(data)) for data in self._training_data])
            median_pieces_length = median([len(pieces) for pieces in train_data_pieces])
            self._pieces_length = min(int(median_pieces_length) + 1, self._pieces_length)
            print(f"Median pieces length: {median_pieces_length}")
            print(f"pieces_length: {self._pieces_length}")

            self._training_data = []  # clear training data to reduce memory usage

    def _train_model(self):
        spm.SentencePieceTrainer.Train(
            input=self._txt_path,
            model_prefix=self._model_path_prefix,
            vocab_size=self._vocab_size,
            model_type=self._model_type,
            split_by_whitespace=False,
            split_by_number=False,
            hard_vocab_limit=False,
            input_sentence_size=1e6,  # max number of sentences to be used for training
            shuffle_input_sentence=True,
        )

    def _to_pieces(self, path: str):
        # This will include the <unk> token
        return self._model.IdToPiece(self._model.EncodeAsIds(path))

    def _calculate(self, syscall: Syscall):
        result = self._feature.get_result(syscall)
        if result is not None:
            pieces = self._to_pieces(result)
            pieces = [piece for piece in pieces if len(piece) > 2]
        else:
            pieces = []
        if self._use_padding:
            zero_padded_pieces = pieces + ["<pad>"] * (self._pieces_length - len(pieces))
            return zero_padded_pieces[:self._pieces_length]
        else:
            if len(pieces) > self._pieces_length:
                return pieces[:self._pieces_length]

    def depends_on(self) -> list:
        return self._dependency_list
