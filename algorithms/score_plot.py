import matplotlib.pyplot as plt
from typing import Type, Optional

from dataloader.syscall import Syscall
from dataloader.base_recording import BaseRecording


# adjusting plot parameters
plt.rcParams.update({"font.size": 20,
                     "figure.figsize": (55, 40),
                     "agg.path.chunksize": 10000,
                     "legend.fontsize": 10,
                     "axes.titlesize": 15,
                     "axes.labelsize": 12,
                     "xtick.labelsize": 10,
                     "ytick.labelsize": 10},)


THRESHOLD_COLOR_LIST = ["teal",
                        "purple",
                        "darkolivegreen",
                        "darkblue",
                        "maroon"]

PLOT_COLOR_LIST = ["cadetblue",
                   "mediumorchid",
                   "olivedrab",
                   "cornflowerblue",
                   "tomato"]

EXPLOIT_COLOR = "lightgray"


class ScorePlot:
    """
    Plot anomaly scores while testing.
    Needs to be initialized in main handed over as parameter to IDS.
    Args:
    building_blocks(list): list of bbs of which threshold and anomaly scores
                           are being extracted. !!! needs to be decider with threshold!!!
    scenario_path(str): scenario path for title of plot.
    filename(str): filename if plot should be persisted.
    Attributes:
    _scenario_path (str):
    """

    def __init__(self,
                 building_blocks: list,
                 scenario_path: str,
                 filename: Optional[str] = None):
        self._scenario_path = scenario_path
        self._bb_list = building_blocks
        self._figure = None
        self._filename = filename
        self._anomaly_scores_exploits = {}
        self._anomaly_scores_no_exploits = {}
        self._first_syscall_of_exploit_recording_index_list = []
        self._first_syscall_of_normal_recording_index_list = []
        self._first_syscall_after_exploit_index_list = []
        self._exploit_time = None
        self._first_sys_after_exploit = False
        self._thresholds = {}
        self._first_syscall_of_cfp_list_exploit = []
        self._last_syscall_of_cfp_list_exploit = []
        self._first_syscall_of_cfp_list_normal = []
        self._last_syscall_of_cfp_list_normal = []

    def set_threshold(self):
        """
        get threshold value from all building blocks
        """

        for bb in self._bb_list:
            try:
                self._thresholds[id(bb)] = bb._threshold
            except AttributeError:
                print("AttributeError")
                print(f'{bb.__class__.__name__} has no threshold value')

    def new_recording(self, recording: Type[BaseRecording]):
        """
        called in ids at beginning of each new recording:
            sets exploit time,
            appends lists of indices of first syscalls of exploit/normal recordings

        """
        if recording.metadata()["exploit"] is True:
            if self._anomaly_scores_exploits:
                self._first_syscall_of_exploit_recording_index_list.append(
                        len(list(self._anomaly_scores_exploits.values())[0]))
            else:
                self._first_syscall_of_normal_recording_index_list.append(0)
            self._exploit_time = recording.metadata()["time"]["exploit"][0]["absolute"]
            self._first_sys_after_exploit = False
        else:
            if self._anomaly_scores_no_exploits:
                self._first_syscall_of_normal_recording_index_list.append(
                        len(list(self._anomaly_scores_no_exploits.values())[0]))
            else:
                self._first_syscall_of_normal_recording_index_list.append(0)
            self._exploit_time = None

    def add_to_plot_data(self, syscall: Syscall, cfa_indices: tuple):
        """
        called in ids for every syscall:
            appends lists of anomaly scores,
            appends syscall indices of exploit starting points to list,
            saves cfa indices given in argument in member lists

        """
        # saving scores separately for plotting
        if self._exploit_time is not None:
            for bb in self._bb_list:
                try:
                    self._anomaly_scores_exploits[id(bb)].append(
                            bb._last_anomaly_score)
                except KeyError:
                    self._anomaly_scores_exploits[id(bb)] = []
                    self._anomaly_scores_exploits[id(bb)].append(
                            bb._last_anomaly_score)
            syscall_time = syscall.timestamp_unix_in_ns() * (10 ** (-9))

            # getting index of first syscall after exploit of each recording for plotting
            if syscall_time >= self._exploit_time and self._first_sys_after_exploit is False:
                self._first_syscall_after_exploit_index_list.append(
                        len(
                            list(self._anomaly_scores_exploits.values())[0]))
                self._first_sys_after_exploit = True

        if self._exploit_time is None:
            for bb in self._bb_list:
                try:
                    self._anomaly_scores_no_exploits[id(bb)].append(
                            bb._last_anomaly_score)
                except KeyError:
                    self._anomaly_scores_no_exploits[id(bb)] = []
                    self._anomaly_scores_no_exploits[id(bb)].append(
                            bb._last_anomaly_score)

        self._first_syscall_of_cfp_list_exploit = cfa_indices[0]
        self._last_syscall_of_cfp_list_exploit = cfa_indices[1]
        self._first_syscall_of_cfp_list_normal = cfa_indices[2]
        self._last_syscall_of_cfp_list_normal = cfa_indices[3]

    def feed_figure(self):

        """
        creates figure with subplots
        """

        self._figure = plt.figure()
        plt.tight_layout(pad=2, h_pad=3, w_pad=3, )
        ax = self._figure.add_subplot(111)  # The big subplot
        ax1 = self._figure.add_subplot(211)
        ax2 = self._figure.add_subplot(212)
        plt.subplots_adjust(hspace=0.4)

        ax.spines['top'].set_color('none')
        ax.spines['bottom'].set_color('none')
        ax.spines['left'].set_color('none')
        ax.spines['right'].set_color('none')
        ax.tick_params(labelcolor='w', top=False, bottom=False, left=False, right=False)

        # first subplot for normal activity
        for i, bb in enumerate(self._bb_list):
            ax1.plot(self._anomaly_scores_no_exploits[id(bb)],
                     PLOT_COLOR_LIST[i],
                     label=f'{bb.__class__.__name__} {i+1}')
            ax1.axhline(y=self._thresholds[id(bb)],
                        color=THRESHOLD_COLOR_LIST[i],
                        label=f'{bb.__class__.__name__} {i+1} Threshold',
                        linewidth=2)
        ax1.legend()

        # cfp windows for normal subplot
        if len(self._first_syscall_of_cfp_list_normal) > 1 and len(self._last_syscall_of_cfp_list_normal) > 1:
            for i, j in zip(self._first_syscall_of_cfp_list_normal, self._last_syscall_of_cfp_list_normal):
                ax1.axvspan(i-1, j-1, color="mediumaquamarine", alpha=0.5)

        # second subplot for exploits
        for i, bb in enumerate(self._bb_list):
            ax2.plot(self._anomaly_scores_exploits[id(bb)],
                     PLOT_COLOR_LIST[i],
                     label=f'{bb.__class__.__name__} {i+1}')
            ax2.axhline(y=self._thresholds[id(bb)],
                        color=THRESHOLD_COLOR_LIST[i],
                        label=f'{bb.__class__.__name__} {i+1} Threshold',
                        linewidth=2)
        ax2.legend()

        # exploit windows for exploit subplot
        self._first_syscall_of_exploit_recording_index_list.append(len(list(
            self._anomaly_scores_exploits.values())[0]))
        exploit_start_index = 0
        exploit_window_end = 0
        recording_start_index = 0
        done = False
        while not done:
            exploit_window_start = self._first_syscall_after_exploit_index_list[exploit_start_index]
            for i in range(recording_start_index, len(self._first_syscall_of_exploit_recording_index_list)):
                if self._first_syscall_of_exploit_recording_index_list[i] > exploit_window_start:
                    exploit_window_end = self._first_syscall_of_exploit_recording_index_list[i]
                    recording_start_index = i
                    break
            ax2.axvspan(exploit_window_start, exploit_window_end, color=EXPLOIT_COLOR)
            exploit_start_index += 1
            if exploit_start_index == len(self._first_syscall_after_exploit_index_list):
                done = True

        # cfp windows for exploit subplot
        for i, j in zip(self._first_syscall_of_cfp_list_exploit, self._last_syscall_of_cfp_list_exploit):
            ax2.axvspan(i, j, color="mediumaquamarine", alpha=0.5)

        # setting labels
        ax1.set_ylabel("anomaly score")
        ax1.set_xlabel("number of systemcalls")
        ax2.set_ylabel("anomaly score")
        ax2.set_xlabel("number of systemcalls")

        ax1.set_title("normal activity")
        ax2.set_title("exploits")
        self._figure.suptitle("Scenario: " + self._scenario_path.split("/")[-1], weight="bold")

    def show_plot(self) -> None:

        """
        shows plot if there is one
        """
        if self._figure is not None:
            if self._filename is None:
                plt.show()
            else:
                plt.savefig(self._filename, dpi=300)
        else:
            "There is no plot to show."

    def save_plot(self, path: str) -> None:

        """
        saving plot as file if there is one,
        input: destination path as string

        """
        if self._figure is not None:
            plt.savefig(path)
        else:
            print("There is no plot to save.")
