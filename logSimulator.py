import time
log_source = './archive/KDDTest+.txt'
history = './records/history.log'
live = './records/temp_log.log'
def simulation(delay=3):
    open(history, 'w').close()
    open(live, 'w').close()
    print('log simulation is starting.....:')
    with open(log_source, 'r') as src:
        for line in src:
            with open(history, 'a') as hist:
                hist.write(f"{line}\n")
            with open(live, 'w') as temp:
                temp.write(f"{line}\n")
            print(f"[+] Relayed to Live & History: {line[:40]}...")
            time.sleep(delay)

if __name__ == "__main__":
    simulation(delay= 2)