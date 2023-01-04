import logging
import os
from dotenv import load_dotenv


load_dotenv(override=True)

logging.basicConfig(
    level=logging.DEBUG,
    # filename="newfile.log",
    format='{asctime} {levelname:<8} {message}',
    style='{',
    # filemode='a'
)

formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')

def setup_logger(name, log_file, level=logging.DEBUG):
    """To setup as many loggers as you want"""

    handler = logging.FileHandler(log_file)
    handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)

    return logger


# events file logger
events_logger = setup_logger('events_logger', os.getenv('EVENTS_LOGGER_FILE_PATH'))

# processed file logger
processed_logger = setup_logger('processed_logger', 'logs/processed.log')


# # first file logger
#     logger = log.setup_logger('first_logger', 'first_logfile.log')
#     logger.info('This is just info message')
#
#     # second file logger
#     super_logger = log.setup_logger('second_logger', 'second_logfile.log')
#     super_logger.error('This is an error message')

# Test messages
# logging.debug("Harmless debug Message")
# logging.info("Just an information")
# logging.warning("Its a Warning")
# logging.error("Did you try to divide by zero")
# logging.critical("Internet is down")