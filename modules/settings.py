def init():
        global PATH_TO_CHROME_DRIVER \
                , NUM_IMPLICITLY_WAIT_SEC \
                , FILE_ENCODING \
                , INT_MAX_ATTEMMPTS_FOR_STALEELEMENT \
                , INT_WAIT_SEC_AFTER_DRIVER_GET
        NUM_IMPLICITLY_WAIT_SEC               = 30
        FILE_ENCODING                         = 'utf-8'
        INT_MAX_ATTEMMPTS_FOR_STALEELEMENT    = 10
        INT_WAIT_SEC_AFTER_DRIVER_GET         = 4
