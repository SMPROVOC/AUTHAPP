import time
from utils import database as db
from utils import models
from utils import logger as log



def switch(state):

    # state can be run, stop, or sleep as integer representing pausing time in seconds
    if state == "run":
        pass

    elif state == "stop":

        # 'stop' only stops for 331 days = 31200000 seconds
        log.events_logger.info('[SWITCH STATE - STOPPED] ALL PROCESSES HAVE BEEN STOPPED BY AN EXTERNAL COMMAND')

        for count in range(31200000):
            time.sleep(1)

            # check for switch status value in database
            switch = db.session.query(models.Settings).filter(models.Settings.id == 1).first()
            db.session.commit()

            if switch.value == "run":
                break

    else:

        # This part converts input into an interger as seconds

        try:
            state = int(state)

            # making sure the sleep is not > 3120000 seconds
            if state > 3120000:
                state = 3120000

            minutes = state / 60

            log.events_logger.info(
                f'[SWITCH STATE - SLEEPING] ALL PROCESSES HAVE BEEN PAUSED BY AN EXTERNAL COMMAND FOR {str(minutes)[:4]} MINUTE(S)')

            for count in range(state):
                time.sleep(1)

                # check for switch status value in database
                switch = db.session.query(models.Settings).filter(models.Settings.id == 1).first()
                db.session.commit()

                if switch.value == "run":
                    break
            switch = db.session.query(models.Settings).filter(models.Settings.id == 1).first()
            switch.value = "run"
            db.session.commit()

        except Exception as e:
            print(e)
#
# switch("stop")

# invalid literal for int() with base 10: 'paushe'