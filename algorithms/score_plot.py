import matplotlib.pyplot as plt

from dataloader.base_recording import BaseRecording
from dataloader.syscall import Syscall

# adjusting plot parameters
plt.rcParams.update({"font.size": 26,
                     "figure.figsize": (55, 40),
                     "agg.path.chunksize": 10000})


class ScorePlot:

    def __init__(self, scenario_path):

        self._scenario_path = scenario_path
        self._figure = None
        self._anomaly_scores_exploits = []
        self._anomaly_scores_no_exploits = []
        self._first_syscall_of_exploit_recording_index_list = []
        self._first_syscall_of_normal_recording_index_list = []
        self._first_syscall_after_exploit_index_list = []
        self._exploit_time = None
        self._first_sys_after_exploit = False
        self.threshold = 0.0
        self._first_syscall_of_cfp_list_exploit = []
        self._last_syscall_of_cfp_list_exploit = []
        self._first_syscall_of_cfp_list_normal = []
        self._last_syscall_of_cfp_list_normal = []

    def new_recording(self, recording: BaseRecording):
        """
        called in ids at beginning of each new recording:
            sets exploit time,
            appends lists of indices of first syscalls of exploit/normal recordings

        """
        if recording.metadata()["exploit"] is True:
            self._first_syscall_of_exploit_recording_index_list.append(len(self._anomaly_scores_exploits))
            self._exploit_time = recording.metadata()["time"]["exploit"][0]["absolute"]
            self._first_sys_after_exploit = False
        else:
            self._first_syscall_of_normal_recording_index_list.append(len(self._anomaly_scores_no_exploits))
            self._exploit_time = None

    def add_to_plot_data(self, score: float, syscall: Syscall, cfa_indices: tuple):
        """
        called in ids for every syscall:
            appends lists of anomaly scores,
            appends syscall indices of exploit starting points to list,
            saves cfa indices given in argument in member lists

        """
        # saving scores separately for plotting
        if self._exploit_time is not None:
            self._anomaly_scores_exploits.append(score)
            syscall_time = syscall.timestamp_unix_in_ns() * (10 ** (-9))

            # getting index of first syscall after exploit of each recording for plotting
            if syscall_time >= self._exploit_time and self._first_sys_after_exploit is False:
                self._first_syscall_after_exploit_index_list.append(len(self._anomaly_scores_exploits))
                self._first_sys_after_exploit = True

        if self._exploit_time is None:
            self._anomaly_scores_no_exploits.append(score)

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
        ax1.plot(self._anomaly_scores_no_exploits)
        ax1.axhline(y=self.threshold, color="g", label="threshold", linewidth=2)
        ax1.legend()

        # cfp windows for normal subplot
        if len(self._first_syscall_of_cfp_list_normal) > 1 and len(self._last_syscall_of_cfp_list_normal) > 1:
            for i, j in zip(self._first_syscall_of_cfp_list_normal, self._last_syscall_of_cfp_list_normal):
                ax1.axvspan(i-1, j-1, color="mediumaquamarine", alpha=0.5)

        # second subplot for exploits
        ax2.plot(self._anomaly_scores_exploits)
        ax2.axhline(y=self.threshold, color="g", label="threshold", linewidth=2)
        ax2.legend()

        # exploit windows for exploit subplot
        self._first_syscall_of_exploit_recording_index_list.append(len(self._anomaly_scores_exploits))
        exploit_start_index = 0
        recording_start_index = 0
        done = False
        while not done:
            exploit_window_start = self._first_syscall_after_exploit_index_list[exploit_start_index]
            for i in range(recording_start_index, len(self._first_syscall_of_exploit_recording_index_list)):
                if self._first_syscall_of_exploit_recording_index_list[i] > exploit_window_start:
                    exploit_window_end = self._first_syscall_of_exploit_recording_index_list[i]
                    recording_start_index = i
                    break
            ax2.axvspan(exploit_window_start, exploit_window_end, color="lightcoral")
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
        self._figure.suptitle("Scenario: " + self._scenario_path.split("/")[-1], fontsize=50, weight="bold")

    def show_plot(self):

        """
        shows plot if there is one
        """
        if self._figure is not None:
            plt.show()
        else:
            "There is no plot to show."

    def save_plot(self, path: str):

        """
        saving plot as file if there is one,
        input: destination path as string

        """
        if self._figure is not None:
            plt.savefig(path)
        else:
            print("There is no plot to save.")
