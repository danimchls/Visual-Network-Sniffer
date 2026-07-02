import matplotlib
from visualizer import Visualizer
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
import threading


class Menu:
    def __init__(self):
        self.visualizer = Visualizer()     

    def run_simulation_mode(self, pcap_file, pps):
        self.visualizer.DEFAULT_PPS = pps
        self.visualizer.SNAPSHOT_INTERVAL = 5
        self.visualizer.fig = plt.figure(figsize=(14, 9))

        threading.Thread(target=self.visualizer.pcap_feeder, args=(pcap_file, self.visualizer.DEFAULT_PPS), daemon=True).start()
        threading.Thread(target=self.visualizer.background_counter, daemon=True).start()
        ani = FuncAnimation(self.visualizer.fig, self.visualizer.animate, interval=1000, cache_frame_data=False)
        plt.show()


    def run_live_mode(self):
        self.visualizer.DEFAULT_PPS = 0
        self.visualizer.SNAPSHOT_INTERVAL = 5
        threading.Thread(target=self.visualizer.sniffer.start_sniffing, daemon=True).start()
        threading.Thread(target=self.visualizer.background_counter, daemon=True).start()

        self.visualizer.fig = plt.figure(figsize=(14, 9))
        ani = FuncAnimation(self.visualizer.fig, self.visualizer.animate, interval=1000, cache_frame_data=False)
        plt.show()
        




