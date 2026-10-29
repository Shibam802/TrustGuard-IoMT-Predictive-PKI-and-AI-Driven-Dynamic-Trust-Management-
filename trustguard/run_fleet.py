"""Launch a fleet of simulated devices in parallel; some get attacked.
Usage: python run_fleet.py [n_devices=8] [n_steps=60] [delay=0.5]
"""
import sys, threading
from device_client import stream_device

n = int(sys.argv[1]) if len(sys.argv) > 1 else 8
steps = int(sys.argv[2]) if len(sys.argv) > 2 else 60
delay = float(sys.argv[3]) if len(sys.argv) > 3 else 0.5
attacked = {1: 35, 4: 42}                      # device index -> attack onset step
names = ["infusion_pump", "ecg_monitor", "ventilator", "glucose_meter", "pulse_oximeter",
         "bp_monitor", "insulin_pump", "defibrillator", "thermometer", "ct_gateway"]
threads = []
for i in range(n):
    did = f"{names[i % len(names)]}_{i:02d}"
    th = threading.Thread(target=stream_device, args=(did, steps, attacked.get(i), 10, delay, 100 + i), daemon=True)
    th.start(); threads.append(th)
print(f"Streaming {n} devices ({steps} steps); attacked devices: {sorted(attacked)}")
for th in threads: th.join()
print("Done.")
