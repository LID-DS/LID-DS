from enum import IntEnum
import matplotlib.pyplot as plt

# adjusting plot parameters
plt.rcParams.update({"font.size": 26,
                     "figure.figsize": (55, 40),
                     "agg.path.chunksize": 10000})


class ExploitParamsIndex(IntEnum):
    THRESHOLD = 0
    FIRST_SYSCALL_AFTER_EXPLOIT_LIST = 1
    FIRST_SYSCALL_OF_RECORDING_LIST = 2
    ANOMALY_SCORES_EXPLOITS = 3
    ANOMALY_SCORES_NO_EXPLOITS = 4


class ScorePlot:

    def __init__(self, scenario_path):

        self._scenario_path = scenario_path
        self._figure = None

    def feed_figure(self, plotting_data: tuple):

        """
        creates figure with subplots

        """
        threshold = plotting_data[ExploitParamsIndex.THRESHOLD]
        first_syscall_after_exploit_list = plotting_data[ExploitParamsIndex.FIRST_SYSCALL_AFTER_EXPLOIT_LIST]
        first_syscall_of_recording_list = plotting_data[ExploitParamsIndex.FIRST_SYSCALL_OF_RECORDING_LIST]
        anomaly_scores_exploits = plotting_data[ExploitParamsIndex.ANOMALY_SCORES_EXPLOITS]
        anomaly_scores_no_exploits = plotting_data[ExploitParamsIndex.ANOMALY_SCORES_NO_EXPLOITS]

        self._figure = plt.figure()
        plt.tight_layout(pad=2, h_pad=3, w_pad=3,)
        ax = self._figure.add_subplot(111)  # The big subplot
        ax1 = self._figure.add_subplot(211)
        ax2 = self._figure.add_subplot(212)

        ax.spines['top'].set_color('none')
        ax.spines['bottom'].set_color('none')
        ax.spines['left'].set_color('none')
        ax.spines['right'].set_color('none')
        ax.tick_params(labelcolor='w', top=False, bottom=False, left=False, right=False)

        # first subplot for normal activity
        ax1.plot(anomaly_scores_no_exploits)
        ax1.axhline(y=threshold, color="g", label="threshold", linewidth=2)
        ax1.legend()

        # second subplot for exploits
        exploit_start_index = 0
        recording_start_index = 0
        done = False
        while not done:
            exploit_window_start = first_syscall_after_exploit_list[exploit_start_index]
            for i in range(recording_start_index, len(first_syscall_of_recording_list)):
                if first_syscall_of_recording_list[i] > exploit_window_start:
                    exploit_window_end = first_syscall_of_recording_list[i]
                    recording_start_index = i
                    break
            ax2.axvspan(exploit_window_start, exploit_window_end, color="lightcoral")
            exploit_start_index += 1
            if exploit_start_index == len(first_syscall_after_exploit_list):
                done = True

        ax2.plot(anomaly_scores_exploits)
        ax2.axhline(y=threshold, color="g", label="threshold", linewidth=2)
        ax2.legend()

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

    def save_plot(self):

        """
        saving plot as .png file if there is one

        """
        if self._figure is not None:
            plt.savefig("anomaly_scores_plot.png")
        else:
            print("There is no plot to save.")

