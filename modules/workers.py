# -*- coding: utf-8 -*-
import sys
import os
import re
import queue
import datetime, time
import traceback
import requests

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from urllib.parse import urlparse
from urllib.parse import unquote
from pathlib import Path
from . import settings, statics

settings.init()
statics.init()

driver = None

flagRunningMOde   = None
numInvalidLink    = None
numExceptions     = None
numHealthyLink    = None
numExternalLinks  = None
numBrowsedPages   = None
numConsoleSevere  = None
numConsoleWarn    = None

# create directory with timestamp to save result files
def init_link_check_worker(__str_start_datetime
                           , __flagRunningMode
                           , __strBaseURL
                           , __strBasicAuthID
                           , __strBasicAuthPassword
                           , __numBrowsedPages
                           , __numHealthyLink                            
                           , __numInvalidLink 
                           , __numExceptions 
                           , __numExternalLinks 
                           , __numConsoleSevere
                           , __numConsoleWarn
                           , __numCriticalExceptions):

        
    global str_start_datetime \
        , flagRunningMode \
        , strBaseURL \
        , strBasicAuthID \
        , strBasicAuthPassword \
        , numBrowsedPages \
        , numHealthyLink \
        , numInvalidLink \
        , numExceptions \
        , numExternalLinks \
        , numConsoleSevere \
        , numConsoleWarn \
        , numCriticalExceptions
    
    str_start_datetime      = __str_start_datetime
    flagRunningMode         = __flagRunningMode
    strBaseURL              = __strBaseURL
    strBasicAuthID          = __strBasicAuthID
    strBasicAuthPassword    = __strBasicAuthPassword
    numBrowsedPages         = __numBrowsedPages
    numHealthyLink          = __numHealthyLink
    numInvalidLink          = __numInvalidLink
    numExceptions           = __numExceptions
    numExternalLinks        = __numExternalLinks
    numConsoleSevere        = __numConsoleSevere
    numConsoleWarn          = __numConsoleWarn
    numCriticalExceptions   = __numCriticalExceptions

    link_check_worker.RESULT_DIRNAME = 'results-' + str_start_datetime

    link_check_worker.FILE_BROWSED_PAGES             = '02.browsed_pages-' + str_start_datetime + '.csv'
    link_check_worker.FILE_OK_LINKS                  = '03.healthy-links-' + str_start_datetime + '.csv'
    link_check_worker.FILE_ERROR_LINKS               = '04.broken_links-' + str_start_datetime + '.csv'
    link_check_worker.FILE_EXTERNAL_LINKS            = '05.external_links-' + str_start_datetime + '.csv'
    link_check_worker.FILE_EXCEPTIONS_ALL            = '06.exceptions-' + str_start_datetime + '.txt'
    link_check_worker.FILE_CONSOLELOG_ALL           = '07.consolelogs-' + str_start_datetime + '.csv'
    link_check_worker.FILE_CRITICALEXCEPTIONS_ALL    = '08.critial_exceptions-' + str_start_datetime + '.txt'
    #Path(link_check_worker.RESULT_DIRNAME, link_check_worker.FILE_BROWSED_PAGES).touch(exist_ok=True) #already created by parent process
    Path(link_check_worker.RESULT_DIRNAME, link_check_worker.FILE_OK_LINKS).touch(exist_ok=True)
    Path(link_check_worker.RESULT_DIRNAME, link_check_worker.FILE_ERROR_LINKS).touch(exist_ok=True)
    Path(link_check_worker.RESULT_DIRNAME, link_check_worker.FILE_EXTERNAL_LINKS).touch(exist_ok=True)
    Path(link_check_worker.RESULT_DIRNAME, link_check_worker.FILE_EXCEPTIONS_ALL).touch(exist_ok=True)
    #Path(link_check_worker.RESULT_DIRNAME, link_check_worker.FILE_CONSOLELOG_ALL).touch(exist_ok=True) #already created by parent process
    Path(link_check_worker.RESULT_DIRNAME, link_check_worker.FILE_CRITICALEXCEPTIONS_ALL).touch(exist_ok=True)


def writeOutMsgToFile(strPathToFile, strMsg, lock):
    try:
        while not lock.acquire(True, 3.0):
            time.sleep(2.0)

        with open(strPathToFile, 'a+', encoding=settings.FILE_ENCODING) as fp:
            fp.write(strMsg + "\n")
    except Exception as ex:
        raise
    finally:
        lock.release()

def writeOutMessageToTmpFile(strPathToFile, strMsg):
    try:
        with open(strPathToFile, 'a+', encoding=settings.FILE_ENCODING) as fp:
            fp.write(strMsg + "\n")
    except Exception as ex:
        raise

def appendAndDeleteTmpFIle(dir_path, f_to, f_tmp, lock):
    try:
        boolIsCopySuccess = False

        if os.path.exists(os.path.join(dir_path, f_tmp)):
            try:
                while not lock.acquire(True, 3.0):
                    time.sleep(2.0)

                with open(os.path.join(dir_path, f_to), 'a+', encoding=settings.FILE_ENCODING) as fp_f_to:
                    with open(os.path.join(dir_path, f_tmp), 'r', encoding=settings.FILE_ENCODING) as fp_f_tmp:
                        fp_f_to.write(fp_f_tmp.read())
                        boolIsCopySuccess = True
            except Exception as ex:
                raise
            finally:
                if boolIsCopySuccess:
                    os.remove(os.path.join(dir_path, f_tmp))
                lock.release()
    except Exception as ex:
        raise


def handleDoubleQuoteForCSV(str_in):
    try:
        return str_in.replace('"', '""')
    except Exception as ex:
        raise

    
def findAllLinks(driver):
    try:
        elems = driver.find_elements(By.XPATH, "//a[@href]")
        elems.extend(driver.find_elements(By.XPATH, "//img[@src]"))
        elems.extend(driver.find_elements(By.XPATH, "//script[@src]"))
        #elems.extend([x for x driver.find_elements(By.XPATH, "//script[@src]") if x.get_attribute("src") != None])
        elems.extend(driver.find_elements(By.XPATH, "//link[@href]"))
        return elems
    except Exception as ex:
        raise
    

def isInternaURL(baseURL, tgtURL):
    try:
        strPtn = '^https?:'
        strBasePath = re.sub(strPtn, '', baseURL)
        strTgtPath = re.sub(strPtn, '', tgtURL)
        return strTgtPath.startswith(strBasePath)
    except Exception as ex:
        raise

# make absolute URL path 
def makeAbsoluteURL(currentBrowsingURL, strLinkPath):
    strAbsoluteURl = ''
    try:
        parsed_linkuri = urlparse(strLinkPath)
        
        if parsed_linkuri.scheme == '':
            parsed_browsing_url = urlparse(currentBrowsingURL)
            if parsed_linkuri.netloc == '':
                # strLinkPath is like /path/to/some/content
                strAbsoluteURL = '{uri.scheme}://{uri.netloc}/{path}'.format(uri=parsed_browsing_url, path=strLinkPath.lstrip('/'))
            else:
                # strLinkPath is like //hostname/path/to/some/content
                strAbsoluteURL = '{uri.scheme}:{path}'.format(uri=parsed_browsing_url, path=strLinkPath)
        else:
            strAbsoluteURL = strLinkPath
        return strAbsoluteURL
    except Exception as ex:
        raise
            
            
# check if response code is redirect
def isRedirect(http_code):
    try:
        # check https://github.com/psf/requests/blob/master/requests/status_codes.py for http status code
        if http_code != requests.codes.ok and \
            http_code in (requests.codes.moved_permanently, requests.codes.see_other, requests.codes.temporary_redirect, requests.codes.permanent_redirect):
                # 301, 303, 307, 308
            return True

        return False
    except Exception as ex:
        raise

# do HEAD / GET request (HEAD if request_type was None)
def doRequest(target_url, request_type=None, argAuth=None, argVerify=None):
    resp = None
    req_method  = None
    try:
        if request_type == 'GET':
            req_method = requests.get
        else:
            req_method = requests.head

        if argAuth is not None and argVerify is not None:
        # basic auth and https
            resp = req_method(target_url, allow_redirects=False, auth=argAuth, verify=argVerify)
        elif argVerify is not None:
            # https without basic auth
            resp = req_method(target_url, allow_redirects=False,verify=argVerify)
        elif argAuth is not None:
            # basic auth
            resp = req_method(target_url, allow_redirects=False,auth=argAuth)
        else:
            # http without basic auth
            resp = req_method(target_url, allow_redirects=False,)

        return resp
    except Exception as ex:
        raise

# check http responce with HEAD / GET request
def getResponse(target_url, request_type=None, basic_auth_id=None, basic_auth_pass=None, boolVerifySsl=None):
    
    resp = None
    argAuth = None
    argVerify = None
    
    try:
        if basic_auth_id is not None and basic_auth_pass is not None:
            argAuth = (basic_auth_id, basic_auth_pass)
        if target_url.startswith('https:'):
            if boolVerifySsl == True:
                argVerify = True
            elif boolVerifySsl == False:
                argVerify = False  # do not check ssl certificate

        resp = doRequest(target_url, request_type, argAuth, argVerify)

        # override encoding by real educated guess as provided by chardet
        # see https://stackoverflow.com/questions/44203397/python-requests-get-returns-improperly-decoded-text-instead-of-utf-8
        resp.encoding = resp.apparent_encoding

        return resp
    except Exception as ex:
        raise

def countup_shared_variable(mp_counter):
    try:
        with mp_counter.get_lock():
            mp_counter.value += 1
    except Exception as ex:
        raise

# if q is empty, wait at most 90 sec.
def carefullyPopTargetURL(q, lock):
    # if no data in q, wait at mmost numMaxSec.
    numPassedSec = 0
    numInterval  = 2
    numMaxSec    = 90
    url = ''
    try:
        while not q and numPassedSec <= numMaxSec:
            time.sleep(numInterval)
            numPassedSec += numInterval

        if q:
            # url exists in q

            try:
                while not lock.acquire(True, 2.0):
                    time.sleep(1.0)
                url = q.pop(0)
            finally:
                lock.release()
            return url
        else:
            # waited 60 sec, but still no url in q -> seems to have no url anymore.
            return None
    except Exception as ex:
        raise
    
def getNetLoc(s):
    try:
        parsed_uri = urlparse(s)
        res = '{uri.scheme}://{uri.netloc}/'.format(uri=parsed_uri)
        return res
    except Exception as ex:
        raise

def getBasicAuthURL(url, basic_auth_id, basic_auth_pass):
    try:
        parsed_url = urlparse(url)
        res = '{uri.scheme}://{uri.netloc}/'.format(uri=parsed_uri)
    except Exception as ex:
        raise
        
    
def link_check_worker(q 
                      , q_browsed_urls 
                      , q_checked_links
                      , lock):
    try:

        # enable browser logging
        d = DesiredCapabilities.CHROME
        #d['loggingPrefs'] = { 'browser':'ALL' }
        d['goog:loggingPrefs'] = { 'browser':'ALL' }
        
        driver = webdriver.Chrome(settings.PATH_TO_CHROME_DRIVER, desired_capabilities=d)
        driver.implicitly_wait(settings.NUM_IMPLICITLY_WAIT_SEC)
        
        while True:

            elems       = []
            f_out_ok    = "f_out_ok_dummy.csv"
            f_out_error = "f_out_error_dummy.csv"
            strCurrentBrowsingURL = None
            
            # try to get the target URL from q. wait max 90 sec if q is empty.            
            strCurrentBrowsingURL = carefullyPopTargetURL(q, lock)

            try:
                while not lock.acquire(True, 2.0):
                    # wait until successfully acquire lock.
                    time.sleep(1.0)
                               
                # must be an atomic operation.
                # popping brosing url and storing it into q_browsed_url are this processe's responsibility.
                
                if not q and strCurrentBrowsingURL is None:
                    # if still no url in q after 90 sec passed, then break.
                    break
                elif q and strCurrentBrowsingURL is None:
                    # colud not get the target url within 90 sec,
                    # but somehow a url is stored in q in very short period while processing from "carefullyPopTargetURL()" to here.
                    strCurrentBrowsingURL = q.pop(0)

                q_browsed_urls.append(strCurrentBrowsingURL)

                strProcessTimestamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f')

                f_out_ok = "__tmp_" + str(os.getpid()) + "_" + strProcessTimestamp + "__healthy_links.csv"
                f_out_error = "__tmp_" + str(os.getpid()) + "_" + strProcessTimestamp + "__broken_links.csv"
                f_out_externalLinks = "__tmp_" + str(os.getpid()) + "_" + strProcessTimestamp + "__external_links.csv"
                f_out_exceptions = "__tmp_" + str(os.getpid()) + "_" + strProcessTimestamp + "__exceptions.txt"
                f_out_consolelog = "__tmp_" + str(os.getpid()) + "_" + strProcessTimestamp + "__console_log.csv"
            finally:
                lock.release()
                
            try:
                
                strLinkType = ''
                strLinkText = ''
                strAltText = ''
                strMsg = ''
                strInternalUrlChkBase = ''

                if flagRunningMode == statics.RUNNING_MODE_TRAVERSAL:
                    # TODO : should have checked if strBaseURL is proper url.
                    strInternalUrlChkBase = strBaseURL
                elif flagRunningMode == statics.RUNNING_MODE_URLLIST:
                    strInternalUrlChkBase = getNetLoc(strCurrentBrowsingURL)

                '''
                # [TODO :eneed to implement] How can I pass through the basic authentication on Chrome? 
                if strBasicAuthID and strBasicAuthPassword:
                    driver.get(getBasicAuthURL(strCurrentBrowsingURL, strBasicAuthID, strBasicAuthPassword))
                else:
                    driver.get(strCurrentBrowsingURL)
                '''
                driver.get(strCurrentBrowsingURL)
                countup_shared_variable(numBrowsedPages)

                
                resp_current_browsing_page = getResponse(strCurrentBrowsingURL, request_type='GET', basic_auth_id=strBasicAuthID, basic_auth_pass=strBasicAuthPassword, boolVerifySsl=True)
                
                if isRedirect(resp_current_browsing_page.status_code):
                    strLocation          = resp_current_browsing_page.headers['Location']
                    strFirstResponse     = resp_current_browsing_page.reason
                    strFIrstStatusCode   = resp_current_browsing_page. status_code
                    strAbsoluteLocation  =  makeAbsoluteURL(strCurrentBrowsingURL, strLocation)
                    resp_redirect        = getResponse(strAbsoluteLocation, basic_auth_id=strBasicAuthID, basic_auth_pass=strBasicAuthPassword, boolVerifySsl = True)
                    
                    strMsg = '"{}","{}","{}",{},{},"{}","{}"'.format(handleDoubleQuoteForCSV(unquote(strCurrentBrowsingURL)) \
                                                                   , '' \
                                                                   , resp_current_browsing_page.status_code\
                                                                   , resp_current_browsing_page.reason \
                                                                   , strLocation \
                                                                   , resp_redirect.status_code \
                                                                   , resp_redirect.reason)
                else:
                    strTitle = ''
                    html_text = resp_current_browsing_page.text
                    # m = re.search('<\W*title\W*(.*)</title', html_text, re.IGNORECASE|re.DOTAL)
                    m = re.search('<*title>(.*)</title', html_text, re.IGNORECASE|re.DOTALL)
                    if m:
                        strTitle = m.group(1)
                        #strTitle.encode(encoding=settings.FILE_ENCODING,errors='ignore')
                    strMsg = '"{}","{}","{}",{},{},"{}","{}"'.format(handleDoubleQuoteForCSV(unquote(strCurrentBrowsingURL)) \
                                                                   , handleDoubleQuoteForCSV(strTitle) \
                                                                   , resp_current_browsing_page.status_code\
                                                                   , resp_current_browsing_page.reason \
                                                                   , '' \
                                                                   , '' \
                                                                   , '')
                writeOutMsgToFile(os.path.join(link_check_worker.RESULT_DIRNAME, link_check_worker.FILE_BROWSED_PAGES), strMsg, lock)
            
                elems = findAllLinks(driver)

                for elem in elems:
                    #print(elem)
                    strAttrHref = None
                    strLinkType = ''
                    strLinkText = ''
                    strAltText = ''
                    strMsg = ''

                    try:

                        try:
                            strLinkType = '<{}>'.format(elem.tag_name)
                        except StaleElementReferenceException:
                            time.sleep(3.0)
                            strLinkType = '<{}>'.format(elem.tag_name)
                        except Exception:
                            raise

                        if elem.tag_name in ('a', 'link'):
                            strAttrHref = elem.get_attribute('href')
                            strLinkText = elem.text
                        elif elem.tag_name in ('img', 'script'):
                            strAttrHref = elem.get_attribute('src')
                            strAltText = '' if elem.get_attribute('alt') == None else elem.get_attribute('alt')

                        strAbsoluteURL = makeAbsoluteURL(strCurrentBrowsingURL, strAttrHref)

                        # if strAbsoluteURL is already checked or is external link, print message.
                        # if it is not checked yet, create message based on the response status and store it into q_checked_links.
                        if strAbsoluteURL in q_checked_links:
                            # already checkecd the status
                            checked_status_code= q_checked_links[strAbsoluteURL]
                            strMsg = '"{}",{},"{}", {},{},,'.format(handleDoubleQuoteForCSV(unquote(strCurrentBrowsingURL)) \
                                                                    , strLinkType \
                                                                    , handleDoubleQuoteForCSV(unquote(strAttrHref)) \
                                                                    , '(visited)'
                                                                    , checked_status_code)
                            
                            #writeOutMessageToTmpFile(os.path.join(link_check_worker.RESULT_DIRNAME, f_out_ok), strMsg) # -> wrong! the link already checkeded does not means it's status is "OK".

                            # increment counter based on the response status.
                            if checked_status_code >= 400:
                                countup_shared_variable(numInvalidLink)
                                writeOutMessageToTmpFile(os.path.join(link_check_worker.RESULT_DIRNAME, f_out_error), strMsg)
                            elif checked_status_code < 0:
                                countup_shared_variable(numExceptions)
                                writeOutMessageToTmpFile(os.path.join(link_check_worker.RESULT_DIRNAME, f_out_exceptions), strMsg)
                            else:
                                countup_shared_variable(numHealthyLink)
                                writeOutMessageToTmpFile(os.path.join(link_check_worker.RESULT_DIRNAME, f_out_ok), strMsg)
                        elif not isInternaURL(strInternalUrlChkBase, strAttrHref):
                            countup_shared_variable(numExternalLinks)
                            strMsg = '"{}",{},"{}", (external link),,,'.format(handleDoubleQuoteForCSV(unquote(strCurrentBrowsingURL)) \
                                                                        , strLinkType \
                                                                        , handleDoubleQuoteForCSV(unquote(strAttrHref)))

                            writeOutMessageToTmpFile(os.path.join(link_check_worker.RESULT_DIRNAME, f_out_externalLinks), strMsg)
                        else:
                            resp_elem = getResponse(strAbsoluteURL, basic_auth_id=strBasicAuthID, basic_auth_pass=strBasicAuthPassword, boolVerifySsl=True)
                            strMsg = '"{}",{},"{}",{},{},"{}","{}"'.format(handleDoubleQuoteForCSV(unquote(strCurrentBrowsingURL)) \
                                                                           , strLinkType \
                                                                           , handleDoubleQuoteForCSV(unquote(strAttrHref)) \
                                                                           , resp_elem.reason \
                                                                           , resp_elem.status_code \
                                                                           , handleDoubleQuoteForCSV(strAltText.replace("\r", '').replace("\n", '')) \
                                                                           , handleDoubleQuoteForCSV(strLinkText.replace("\r", '').replace("\n", '')))
                            # save url and status_code
                            if not strAbsoluteURL in q_checked_links:
                                q_checked_links[strAbsoluteURL] = resp_elem.status_code

                            if flagRunningMode == statics.RUNNING_MODE_TRAVERSAL:
                                # store link into q if its internalinternal of considering url.
                                try:
                                   while not lock.acquire(True, 2.0):
                                       # wait until successfully acquire lock.
                                       time.sleep(2.0)

                                   if resp_elem.status_code > 0 and resp_elem.status_code < 400 \
                                       and not ('mailto:' in strAttrHref or 'tel:' in strAttrHref) \
                                       and elem.tag_name == 'a' \
                                       and (not strAbsoluteURL in q_browsed_urls) and (not strAbsoluteURL in q) \
                                       and (not strAttrHref.rfind('#') > strAttrHref.rfind('/')) \
                                       and not (strAttrHref.endswith('.png') or strAttrHref.endswith('.jpg') or strAttrHref.endswith('.gif')) \
                                       and isInternaURL(strInternalUrlChkBase, strAttrHref):
                                        q.append(strAbsoluteURL)
                                finally:
                                    lock.release()

                            # increment counter based on the response status.
                            if resp_elem.status_code >= 400:
                                countup_shared_variable(numInvalidLink)
                                writeOutMessageToTmpFile(os.path.join(link_check_worker.RESULT_DIRNAME, f_out_error), strMsg)
                            elif resp_elem.status_code < 0:
                                countup_shared_variable(numExceptions)
                                writeOutMessageToTmpFile(os.path.join(link_check_worker.RESULT_DIRNAME, f_out_exceptions), strMsg)
                            else:
                                countup_shared_variable(numHealthyLink)
                                writeOutMessageToTmpFile(os.path.join(link_check_worker.RESULT_DIRNAME, f_out_ok), strMsg)
                    except Exception as ex:
                        exc_type, exc_value, exc_traceback = sys.exc_info()
                        sam =  traceback.format_exception(exc_type, exc_value, exc_traceback)

                        strMsg = '"{}",' \
                                'Tag: "{}",' \
                                'At attribute : "{}",' \
                                '[Exception] @class : {},' \
                                '@in : {},' \
                                'Message : {},' \
                                '"{}"'.format(handleDoubleQuoteForCSV(unquote(strCurrentBrowsingURL)) \
                                              , elem.tag_name \
                                              , elem.get_attribute('innerHTML') \
                                              , ex.__class__.__name__ \
                                              , sys._getframe().f_code.co_name \
                                              , repr(traceback.format_stack()) \
                                              , '')
                        countup_shared_variable(numExceptions)
                        writeOutMessageToTmpFile(os.path.join(link_check_worker.RESULT_DIRNAME, f_out_exceptions), strMsg)
                    # --- end of outer try in for elem in elems:
                # --- end of for elem in elems:



                strConsoleLog = ''
                for cl in driver.get_log('browser'):
                    strConsoleLog += '{},"{}",{},{},{}\n'.format(cl['level'] \
                                                                 , handleDoubleQuoteForCSV(cl['message']) \
                                                                 , cl['source'] \
                                                                 , datetime.datetime.fromtimestamp(float(cl['timestamp']/1000)).strftime('%Y%m%d-%H%M%S-%f') \
                                                                 , strCurrentBrowsingURL)

                    if cl['level'] == 'SEVERE':
                        countup_shared_variable(numConsoleSevere)
                    elif cl['level'] == 'WARNING':
                        countup_shared_variable(numConsoleWarn)
                if strConsoleLog != '':
                    writeOutMessageToTmpFile(os.path.join(link_check_worker.RESULT_DIRNAME, f_out_consolelog), strConsoleLog)
                strConsoleLog = ''

                
            except Exception as ex:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                sam =  traceback.format_exception(exc_type, exc_value, exc_traceback)
                
                strMsg = '{},' \
                    '{},' \
                    '"{}",' \
                    '{},' \
                    '{},' \
                    '{},' \
                    '{}"'.format( sys._getframe().f_code.co_name + 'is going to terminate due to unexpected exception at ' + datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f')\
                                  , ex.__class__.__name__ \
                                  #, repr(traceback.format_stack()) \
                                  #, str(traceback.format_stack()) \
                                  , str(traceback.format_tb(ex.__traceback__)) \
                                  , '' \
                                  , '' \
                                  , '' \
                                  , '')
                countup_shared_variable(numCriticalExceptions)
                writeOutMsgToFile(os.path.join(link_check_worker.RESULT_DIRNAME, link_check_worker.FILE_CRITICALEXCEPTIONS_ALL), strMsg, lock)
                break # break the most outer while
                
            finally:
                appendAndDeleteTmpFIle(link_check_worker.RESULT_DIRNAME, link_check_worker.FILE_OK_LINKS, f_out_ok, lock)
                appendAndDeleteTmpFIle(link_check_worker.RESULT_DIRNAME, link_check_worker.FILE_ERROR_LINKS, f_out_error, lock)
                appendAndDeleteTmpFIle(link_check_worker.RESULT_DIRNAME, link_check_worker.FILE_EXTERNAL_LINKS, f_out_externalLinks, lock)
                appendAndDeleteTmpFIle(link_check_worker.RESULT_DIRNAME, link_check_worker.FILE_EXCEPTIONS_ALL, f_out_exceptions, lock)
                appendAndDeleteTmpFIle(link_check_worker.RESULT_DIRNAME, link_check_worker.FILE_CONSOLELOG_ALL, f_out_consolelog, lock)
            # --- end of inner try ---
        # --- end of while q: ---
    # --- end of outer try: ---

    except Exception as ex:
        # some unexpected exception
        exc_type, exc_value, exc_traceback = sys.exc_info()
        sam =  traceback.format_exception(exc_type, exc_value, exc_traceback)
        strMsg = '{},' \
            '{},' \
            '"{}",' \
            '{},' \
            '{},' \
            '{},' \
            '{}"'.format( sys._getframe().f_code.co_name\
                          , ex.__class__.__name__ \
                          , str(traceback.format_tb(ex.__traceback__)) \
                          , '' \
                          , '' \
                          , '' \
                          , '')
        countup_shared_variable(numExceptions)
        writeOutMsgToFile(os.path.join(link_check_worker.RESULT_DIRNAME, link_check_worker.FILE_CRITICALEXCEPTIONS_ALL), strMsg, lock)
        raise
    finally:
        driver.close()
        driver.quit()