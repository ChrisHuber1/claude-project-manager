import threading
import time

_last_alert_time = 0
_alert_lock = threading.Lock()
_engine = None
_engine_ok = False


def _init_engine():
    global _engine, _engine_ok
    try:
        import pyttsx3
        _engine = pyttsx3.init()
        _engine_ok = True
    except Exception:
        _engine_ok = False


def speak(text):
    global _last_alert_time
    with _alert_lock:
        now = time.time()
        if now - _last_alert_time < 60:
            return False
        _last_alert_time = now

    if _engine is None:
        _init_engine()

    if _engine_ok:
        try:
            _engine.say(text)
            _engine.runAndWait()
            return True
        except Exception:
            return False
    return False


def alert_input_needed():
    return speak("Master we need your input")
