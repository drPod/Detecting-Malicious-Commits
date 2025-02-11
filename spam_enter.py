import time
import pyautogui
from AppKit import NSWorkspace
import sys


def is_app_active(app_name):
    """Check if the specified app is active"""
    active_app = NSWorkspace.sharedWorkspace().activeApplication()
    return app_name.lower() in active_app["NSApplicationName"].lower()


def countdown_and_press(app_name):
    print(f"Target app: {app_name}")
    print("Move mouse to top-left corner to abort")
    print("Starting in 5...")

    # Countdown
    for i in range(5, 0, -1):
        print(i)
        time.sleep(1)

    # Check app and press enter
    while True:  # Loop until stopped
        if is_app_active(app_name):
            print("Pressing Enter...")
            pyautogui.press("enter")
            time.sleep(0.01)
        else:
            print(f"Please switch to {app_name}!")
            time.sleep(1)


if __name__ == "__main__":
    pyautogui.FAILSAFE = True

    # Get app name
    app_name = input("Enter application name (e.g., 'Chrome', 'Notes'): ")

    try:
        countdown_and_press(app_name)
    except KeyboardInterrupt:
        print("\nStopped")
        sys.exit(0)
