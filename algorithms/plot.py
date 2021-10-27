import matplotlib.pyplot as plt

from dataloader.base_data_loader import BaseDataLoader


class ExploitPlot:

    def __init__(self, plotting_data: tuple, dataloader: BaseDataLoader):
        self._threshold = plotting_data[0]
        self._first_syscall_after_exploit_list = plotting_data[1]
        self._first_syscall_of_recording_list = plotting_data[2]
        self._anomaly_scores_exploits = plotting_data[3]
        self._anomaly_scores_no_exploits = plotting_data[4]
        self._data_loader = dataloader

    def plot_performance(self):

        """
        creates 2 plots: normal activity and exploit cases

        """
        plt.rcParams.update({"font.size": 26,
                             "figure.figsize": (55, 40),
                             "agg.path.chunksize": 10000})

        fig = plt.figure()
        ax = fig.add_subplot(111)  # The big subplot
        ax1 = fig.add_subplot(211)
        ax2 = fig.add_subplot(212)

        ax.spines['top'].set_color('none')
        ax.spines['bottom'].set_color('none')
        ax.spines['left'].set_color('none')
        ax.spines['right'].set_color('none')
        ax.tick_params(labelcolor='w', top=False, bottom=False, left=False, right=False)

        # first subplot for normal activity
        ax1.plot(self._anomaly_scores_no_exploits)
        ax1.axhline(y=self._threshold, color="g", label="threshold", linewidth=2)
        ax1.legend()

        # second subplot for exploits

        exploit_start_index = 0
        recording_start_index = 0
        done = False
        while not done:
            exploit_window_start = self._first_syscall_after_exploit_list[exploit_start_index]
            for i in range(recording_start_index, len(self._first_syscall_of_recording_list)):
                if self._first_syscall_of_recording_list[i] > exploit_window_start:
                    exploit_window_end = self._first_syscall_of_recording_list[i]
                    recording_start_index = i
                    break
            ax2.axvspan(exploit_window_start, exploit_window_end, color="lightcoral")
            exploit_start_index += 1
            if exploit_start_index == len(self._first_syscall_after_exploit_list):
                done = True

        ax2.plot(self._anomaly_scores_exploits)
        ax2.axhline(y=self._threshold, color="g", label="threshold", linewidth=2)
        ax2.legend()

        # Set labels
        ax1.set_ylabel("anomaly score")
        ax1.set_xlabel("number of systemcalls")
        ax2.set_ylabel("anomaly score")
        ax2.set_xlabel("number of systemcalls")

        ax1.set_title("normal activity")
        ax2.set_title("exploits")
        fig.suptitle("Scenario: " + self._data_loader.get_scenario_name(), fontsize=50, weight="bold")
        plt.show()
