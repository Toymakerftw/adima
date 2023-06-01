from apscheduler.schedulers.background import BackgroundScheduler
import subprocess

def dump_and_analyze():
    # Execute dump.py
    subprocess.run(['python', 'dump.py'])

    # Execute analyze.py
    subprocess.run(['python', 'analyze.py'])

def start_scheduler():
    scheduler = BackgroundScheduler()
    scheduler.add_job(dump_and_analyze, 'interval', minutes=10)
    scheduler.start()

    # Keep the Flask app running
    while True:
        try:
            pass
        except (KeyboardInterrupt, SystemExit):
            scheduler.shutdown()
            break

if __name__ == '__main__':
    start_scheduler()
