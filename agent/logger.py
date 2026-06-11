import logging
import json
import os


class JsonFormatter(logging.Formatter):
    """
    Formats log records as single-line JSON objects.
    Cloud Run ingests these as structured logs — searchable and filterable in GCP Console.
    """
    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "severity": record.levelname,
            "message": record.getMessage(),
            "module": record.module,
            "funcName": record.funcName,
        }
        return json.dumps(log_entry)


def get_logger(name: str) -> logging.Logger:
    """
    Returns a logger configured with JSON output.
    Each module gets its own named logger for easier filtering in Cloud Run logs.
    """
    logger = logging.getLogger(name)

    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False

    return logger