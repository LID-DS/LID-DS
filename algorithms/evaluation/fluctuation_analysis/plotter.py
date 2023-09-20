from matplotlib import pyplot as plt
from matplotlib.figure import Figure

from algorithms.evaluation.fluctuation_analysis.anomaly_scores import AnomalyScores


def plot_scores_single_epoch(anos: AnomalyScores, ax: plt.Axes, with_exclusion=False):
    if with_exclusion:
        ax.plot(anos.normal_exc_train, ['nt'] * len(anos.normal_exc_train), "x", color='cyan')
        ax.plot(anos.before_exploit_exc_train, ['bt'] * len(anos.before_exploit_exc_train), "x", color='green')
        ax.plot(anos.after_exploit_exc_train, ['at'] * len(anos.after_exploit_exc_train), "x", color='red')
        ax.plot(anos.val_exc_train, ['vt'] * len(anos.val_exc_train), "x", color='black')
        ax.plot([max(anos.val_exc_train)] * 4, ['vt', 'bt', 'at', 'nt'], "r")

    ax.plot(anos.normal, ['n'] * len(anos.normal), "x", color='cyan')
    ax.plot(anos.before_exploit, ['b'] * len(anos.before_exploit), "x", color='green')
    ax.plot(anos.after_exploit, ['a'] * len(anos.after_exploit), "x", color='red')
    ax.plot(anos.val, ['v'] * len(anos.val), "x", color='blue')
    ax.plot(anos.train, ['t'] * len(anos.train), "x", color='orange')
    ax.plot([anos.threshold] * 5, ['v', 'b', 'a', 'n', 't'], "r")

    return ax


def plot_before_after_scores_single_recording(_anos: AnomalyScores, _ax: plt.Axes):
    as_before = _anos.before_exploit
    as_after = _anos.after_exploit
    threshold = _anos.threshold

    _ax.plot(range(len(as_before) + len(as_after)), (len(as_before) + len(as_after)) * [threshold], color='red')
    _ax.plot(range(len(as_before)), as_before, "x", color='green')
    _ax.plot(range(len(as_before), len(as_before) + len(as_after)), as_after, "x", color='orange')
    _ax.grid(False)
    return _ax


def plot_ths_detected_counts(anos_s: list[AnomalyScores], train_losses: dict = None, val_losses: dict = None):
    thresholds = [_anos.threshold for _anos in anos_s]
    thresholds_train = [_anos.threshold_train for _anos in anos_s]
    detected_counts = [sum(_anos.detected) for _anos in anos_s]
    false_positives_counts = [sum(_anos.false_positives) for _anos in anos_s]
    true_anos_counts = [_anos.true_anomal_ngs_count for _anos in anos_s]
    epochs = [_anos.epoch for _anos in anos_s]

    fig: Figure
    fig, (ax, ax2, ax3) = plt.subplots(1, 3)
    fig.set_figheight(10)
    fig.set_figwidth(30)

    lx1 = ax.plot(epochs, thresholds, label="threshold", marker="x", color="green", linestyle="-.")
    lx2 = ax.plot(epochs, thresholds_train, label="threshold_train", marker="o", )
    lns = lx1 + lx2
    if train_losses is not None:
        ax12 = ax.twinx()
        xes = train_losses.keys()
        lx12 = ax12.plot(xes, train_losses.values(), label="train_losses", color="blue", linestyle="-")
        lx13 = ax12.plot(xes, val_losses.values(), label="val_losses", color="red", linestyle="-")
        lns += lx12 + lx13
    labs = [l.get_label() for l in lns]
    ax.legend(lns, labs, loc=0)

    ax2.plot(epochs, detected_counts, label="detected_counts", color="green", marker="x", linestyle="-", linewidth=1)
    ax2.scatter(epochs, false_positives_counts, label="false_positives_counts", color="red", marker="x")
    ax2.legend()

    ax3.scatter(epochs, true_anos_counts, label="true counts", marker="x")
    ax3.legend()

    return fig


def plot_scores_over_epochs(anos_s: list[AnomalyScores],
                            ax_d: plt.Axes,
                            log_scale=False,
                            thresholds=None,
                            bigger_marked=False,
                            title="Anomaly scores over epochs"):
    thresholds = thresholds or [_anos.threshold for _anos in anos_s]
    epochs = [_anos.epoch for _anos in anos_s]

    for _anos in anos_s:
        detected = [score for score in _anos.after_exploit if score > _anos.threshold]
        false_positive = [score for score in _anos.before_exploit if score > _anos.threshold]
        ax_d.plot(
            [_anos.epoch - 0.5] * len(_anos.before_exploit),
            _anos.before_exploit,
            "x",
            color='green',
            label="before exploit",
            markersize=2
        )
        if bigger_marked:
            ax_d.plot(
                [_anos.epoch - 0.5] * len(false_positive),
                false_positive,
                "x",
                color="green",
                markersize=8,
            )
        ax_d.plot(
            [_anos.epoch + 0.5] * len(_anos.after_exploit),
            _anos.after_exploit,
            "x",
            color='red',
            label="after exploit",
            alpha=0.6,
            markersize=2
        )
        if bigger_marked:
            ax_d.plot(
                [_anos.epoch + 0.5] * len(detected),
                detected,
                "x",
                color="red",
                markersize=8,
            )

    ax_d.plot(epochs, thresholds, color='black', label='threshold', markersize=10, linestyle='--')
    if log_scale:
        ax_d.set_yscale('log')

    legend_entries = [
        ax_d.plot([], [], 'x', color='green', label='before exploit')[0],
        ax_d.plot([], [], 'x', color='red', label='after exploit', markersize=2)[0],
        ax_d.plot([], [], color='black', label='threshold', markersize=2)[0],
    ]
    ax_d.legend(handles=legend_entries)
    ax_d.set_xlabel("epochs")
    ax_d.set_ylabel("anomaly score")
    ax_d.set_title(title)
