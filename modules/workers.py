# -*- coding: utf-8 -*-
import sys
import os
import re
import queue
import datetime, time
import traceback
import requests
import base64
import csv

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import StaleElementReferenceException
from urllib.parse import urlparse
from urllib.parse import unquote
from pathlib import Path
from . import settings, statics

from selenium import webdriver
from webdriver_manager.chrome import ChromeDriverManager

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
                           , __numCriticalExceptions
                           , __boolVerifySSLCertIN
                           , __boolFollowRedirectIN):

        
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
        , numCriticalExceptions \
        , boolVerifySSLCertIN \
        , boolFollowRedirectIN
    
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
    boolVerifySSLCertIN     = __boolVerifySSLCertIN
    boolFollowRedirectIN    = __boolFollowRedirectIN

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


def writeOutMsgToFile(strPathToFile, arrOutput, lock):
    try:
        while not lock.acquire(True, 3.0):
            time.sleep(2.0)

        with open(strPathToFile, 'a+', encoding=settings.FILE_ENCODING) as fp:
            csvwriter = csv.writer(fp
                                   , delimiter=','
                                   , quotechar='"'
                                   , quoting=csv.QUOTE_ALL
                                   , lineterminator="\n" )
            if arrOutput and type(arrOutput[0]) is list:
                # mostly in case of console log (array of array)
                csvwriter.writerows(arrOutput)
            else:
                csvwriter.writerow(arrOutput)
    except Exception as ex:
        raise
    finally:
        lock.release()

def writeOutMessageToTmpFile(strPathToFile, arrOutput):
    try:
        with open(strPathToFile, 'a+', encoding=settings.FILE_ENCODING) as fp:
            csvwriter = csv.writer(fp
                                   , delimiter=','
                                   , quotechar='"'
                                   , quoting=csv.QUOTE_ALL
                                   , lineterminator="\n" )
            if arrOutput and type(arrOutput[0]) is list:
                # mostly in case of console log (array of array)
                csvwriter.writerows(arrOutput)
            else:
                csvwriter.writerow(arrOutput)
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
    

def isInternalURL(baseURL, tgtURL):
    try:
        strPtn = '^https?:'
        strBasePath = re.sub(strPtn, '', baseURL)
        strTgtPath = re.sub(strPtn, '', tgtURL)
        return strTgtPath.startswith(strBasePath)
    except Exception as ex:
        raise

# make absolute URL path 
def makeAbsoluteURL(currentBrowsingURL, strLinkPath, keepScheme = False):
    strAbsoluteURl = ''
    try:
        
        parsed_browsing_url = urlparse(currentBrowsingURL)
        parsed_linkuri = urlparse(strLinkPath)
        
        if parsed_linkuri.scheme == '':
            if parsed_linkuri.netloc == '':
                # strLinkPath is like /path/to/some/content
                strAbsoluteURL = '{uri.scheme}://{uri.netloc}/{path}'.format(uri=parsed_browsing_url, path=strLinkPath.lstrip('/'))
            else:
                # strLinkPath is like //hostname/path/to/some/content
                strAbsoluteURL = '{uri.scheme}:{path}'.format(uri=parsed_browsing_url, path=strLinkPath)
        elif keepScheme:
            strPtn = '^https?:'
            strLinkPath = re.sub(strPtn, '', strLinkPath)
            strSlashSlash =''
            
            if parsed_linkuri.netloc == '':
                strSlashSlash = '//'
            strAbsoluteURL = '{uri.scheme}:{slash_slash}{path}'.format(uri=parsed_browsing_url, slash_slash=strSlashSlash, path=strLinkPath)
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
            http_code in (requests.codes.moved_permanently
                          , requests.codes.found
                          , requests.codes.see_other
                          , requests.codes.temporary_redirect
                          , requests.codes.permanent_redirect):
                # 301, 302, 303, 307, 308
            return True

        return False
    except Exception as ex:
        raise

# do HEAD / GET request (HEAD if request_type was None)
def doRequest(
        target_url
        , argFollowRedirect
        , request_type=None
        , argAuth=None
        , argVerify=None):

    resp = None
    req_method  = None
    try:
        if request_type == 'GET':
            req_method = requests.get
        else:
            req_method = requests.head
            
        if argAuth is not None and argVerify is not None:
        # basic auth and https
            resp = req_method(target_url, allow_redirects=argFollowRedirect, auth=argAuth, verify=argVerify)
        elif argVerify is not None:
            # https without basic auth
            resp = req_method(target_url, allow_redirects=argFollowRedirect, verify=argVerify)
        elif argAuth is not None:
            # basic auth
            resp = req_method(target_url, allow_redirects=argFollowRedirect, auth=argAuth)
        else:
            # http without basic auth
            resp = req_method(target_url, allow_redirects=argFollowRedirect,)

        
        return resp
    except Exception as ex:
        raise

# check http responce with HEAD / GET request
def getResponse(
        target_url
        , boolFollowRedirect
        , request_type=None
        , basic_auth_id=None
        , basic_auth_pass=None
        , boolVerifySsl=None):
    
    resp = None
    argAuth = None
    argVerify = None
    argFollowRedirect = False

    try:
        if basic_auth_id is not None and basic_auth_pass is not None:
            argAuth = (basic_auth_id, basic_auth_pass)
        if target_url.startswith('https:'):
            if boolVerifySsl == True:
                argVerify = True
            elif boolVerifySsl == False:
                argVerify = False  # do not check ssl certificate

        # in case redirect http to https
        argVerify = boolVerifySsl
        argFollowRedirect = boolFollowRedirect

        resp = doRequest(target_url, argFollowRedirect, request_type, argAuth, argVerify)

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
                # there could be two cases for q to be empty.
                #   1. q is still empty after numMaxSec sec of waiting -> seems to have no url to check anymore.
                #   2. q became empty while taking a lock.
                # -> return None in each case.
                url = q.pop(0) if q else None # will be None in case q became empty while taking a lock.
            except Exception as ex:
                raise
            else:
                return url
            finally:
                lock.release()
        else:
            # waited numMaxSec sec, but still no url in q -> seems to have no url anymore.
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
        d['acceptInsecureCerts'] = True

        options = Options()
        options.add_argument('--ignore-certificate-errors')

        
        #driver = webdriver.Chrome(settings.PATH_TO_CHROME_DRIVER, desired_capabilities=d, options=options)
        driver = webdriver.Chrome(ChromeDriverManager().install(), desired_capabilities=d, options=options)
        driver.implicitly_wait(settings.NUM_IMPLICITLY_WAIT_SEC)
        
        while True:

            elems       = []
            f_out_ok    = "f_out_ok_dummy.csv"
            f_out_error = "f_out_error_dummy.csv"
            strCurrentBrowsingURL = None
            strElementCheckingURL = ''
            
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
                arrOutput = []
                strInternalUrlChkBase = ''

                if flagRunningMode == statics.RUNNING_MODE_TRAVERSAL:
                    # TODO : should have checked if strBaseURL is proper url.
                    strInternalUrlChkBase = strBaseURL
                elif flagRunningMode == statics.RUNNING_MODE_URLLIST:
                    strInternalUrlChkBase = getNetLoc(strCurrentBrowsingURL)


                # 1st. access to strCurrentBrowsingURL via requests() and get location's url in case 30x (since webdriver does not follow 30x).
                # 2nd. if 30x, rewrite strCurrentBrowsingURL to location's url
                # 3rd. access to strCurrentBrowsingURL using webdriver (driver.get()).

                ###########
                # 1st
                ###########
                # first, get a response without redirect
                resp_current_browsing_page = getResponse(strCurrentBrowsingURL
                                                         , False
                                                         , request_type='GET'
                                                         , basic_auth_id=strBasicAuthID
                                                         , basic_auth_pass=strBasicAuthPassword
                                                         , boolVerifySsl=boolVerifySSLCertIN)

                strContentType = resp_current_browsing_page.headers['content-type'].casefold()
                if 'text/html' not in strContentType:
                    arrOutput = [unquote(strCurrentBrowsingURL)
                                 , strContentType  # content-type, reason of skipping
                                 , resp_current_browsing_page.status_code
                                 , resp_current_browsing_page.reason
                                 , ''
                                 , ''
                                 , '']
                    countup_shared_variable(numBrowsedPages)
                    writeOutMsgToFile(os.path.join(link_check_worker.RESULT_DIRNAME, link_check_worker.FILE_BROWSED_PAGES), arrOutput, lock)
                    continue
                '''
                # in case a binary file (such as pdf, image, xls, zip), skip detail check
                # -> [TODO] shold check content-type in the response header to be more precisely.
                strSkipFilePtn = '\.(gif|jpg||jpeg|png|pdf|exe|xls|xlsx|mp4|ico|svg|zip)$'
                skipFileMatch = re.search(strSkipFilePtn, strCurrentBrowsingURL, re.IGNORECASE)
                if skipFileMatch:
                    arrOutput = [unquote(strCurrentBrowsingURL)
                                 , skipFileMatch.group(1)  # output the file extension
                                 , resp_current_browsing_page.status_code
                                 , resp_current_browsing_page.reason
                                 , ''
                                 , ''
                                 , '']
                    countup_shared_variable(numBrowsedPages)
                    writeOutMsgToFile(os.path.join(link_check_worker.RESULT_DIRNAME, link_check_worker.FILE_BROWSED_PAGES), arrOutput, lock)
                    continue
                '''
                
                if isRedirect(resp_current_browsing_page.status_code):
                    #strLocation          = resp_current_browsing_page.headers['Location']
                    # Some reverse proxy (IIS) returns the location string as "mojibake".
                    strLocation          = resp_current_browsing_page.headers['Location'].encode("latin-1").decode("utf-8")
                    strFirstResponse     = resp_current_browsing_page.reason
                    strFIrstStatusCode   = resp_current_browsing_page.status_code
                    strAbsoluteLocation  = makeAbsoluteURL(strCurrentBrowsingURL, strLocation)
                    resp_recirect        = None

                    if boolFollowRedirectIN is False:
                        # just check the status of next location.
                        resp_redirect        = getResponse(strAbsoluteLocation
                                                           , boolFollowRedirectIN
                                                           #, basic_auth_id=strBasicAuthID
                                                           #, basic_auth_pass=strBasicAuthPassword
                                                           , boolVerifySsl = boolVerifySSLCertIN)
                        
                        arrOutput = [unquote(strCurrentBrowsingURL)
                                 , ''
                                 , resp_current_browsing_page.status_code
                                 , resp_current_browsing_page.reason
                                 , unquote(strLocation)
                                 , resp_redirect.status_code
                                 , resp_redirect.reason]
                        
                    else:
                        # follow the redirect chain and obtain all history.
                        resp_redirect        = getResponse(strCurrentBrowsingURL
                                                           , boolFollowRedirectIN
                                                           , basic_auth_id=strBasicAuthID
                                                           , basic_auth_pass=strBasicAuthPassword
                                                           , boolVerifySsl = boolVerifySSLCertIN)

                        # we already know it's redirect so that resp_redirect should always have a history data.
                        for i, r in enumerate(resp_redirect.history):
                            if i == 0:
                                arrOutput.extend([unquote(r.url)
                                                  , ''
                                                  , r.status_code
                                                  , r.reason ])
                            else:
                                arrOutput.extend([unquote(r.url), r.status_code, r.reason])

                    #
                    # after taken necessary information for logging, do 2nd.
                    #
                    ###########
                    # 2nd
                    ###########
                    # to avoid an exception in case 30x redirect on opening url by driver.get(URL)
                    #if isInternalURL(strBaseURL, strAbsoluteLocation):
                    if isInternalURL(strInternalUrlChkBase, strAbsoluteLocation):
                        # keep the protocol
                        strAbsoluteLocation  = makeAbsoluteURL(strCurrentBrowsingURL, strLocation, keepScheme = True)
                        strCurrentBrowsingURL = strAbsoluteLocation
                    else:
                        strCurrentBrowsingURL = strAbsoluteLocation
                                
                        # output the final state of request rather than the last of chain.
                        arrOutput.extend([unquote(resp_redirect.url), resp_redirect.status_code, resp_redirect.reason])

                    strElementCheckingURL = resp_redirect.url
                                
                else:
                    strTitle = ''
                    strFinalURL = ''
                    html_text = resp_current_browsing_page.text
                    # m = re.search('<\W*title\W*(.*)</title', html_text, re.IGNORECASE|re.DOTAL)
                    m = re.search('<*title>(.*?)</title', html_text, re.IGNORECASE|re.DOTALL)
                    if m:
                        strTitle = m.group(1)
                        #strTitle.encode(encoding=settings.FILE_ENCODING,errors='ignore')

                    arrOutput = [unquote(strCurrentBrowsingURL)
                                 , strTitle
                                 , resp_current_browsing_page.status_code
                                 , resp_current_browsing_page.reason
                                 , ''
                                 , ''
                                 , '']
                    
                    strElementCheckingURL = strCurrentBrowsingURL

                ###########
                # 3rd
                ###########
                
                # now open the page with browser.
                driver.execute_cdp_cmd("Network.enable", {})
                driver.execute_cdp_cmd("Network.clearBrowserCache", {})
                
                # to handle Basic Auth, execute Chrome Devtools Protocol command.
                if strBasicAuthID and strBasicAuthPassword:
                    auth = base64.b64encode('{}:{}'.format(strBasicAuthID, strBasicAuthPassword).encode('utf-8')).decode('utf-8')
                    driver.execute_cdp_cmd("Network.setExtraHTTPHeaders", {"headers": {"Authorization": "Basic " + auth}})
                    # (note)
                    # don't have to clear header, like
                    # "driver.execute_cdp_cmd("Network.setExtraHTTPHeaders", {"headers": {}})"
                    # , since I don't pass the request to external link (see: isInternalURL()).

                driver.get(strCurrentBrowsingURL)
                #driver.navigate().to(strCurrentBrowsingURL) # does not work even access to the first URL raises exception

                countup_shared_variable(numBrowsedPages)
                time.sleep(settings.INT_WAIT_SEC_AFTER_DRIVER_GET) # just wait a little bit to avoid StaleElementReferenceException.
                
                writeOutMsgToFile(os.path.join(link_check_worker.RESULT_DIRNAME, link_check_worker.FILE_BROWSED_PAGES), arrOutput, lock)

                #
                # --- beginning of element cheging ---
                #
            
                elems = findAllLinks(driver)

                for elem in elems:
                    #print(elem)
                    strAttrHref = None
                    strLinkType = ''
                    strLinkText = ''
                    strAltText = ''
                    arrOutput = []
                    intAttempts = 0

                    try:

                        while intAttempts < settings.INT_MAX_ATTEMMPTS_FOR_STALEELEMENT:
                            try:
                                strLinkType = '<{}>'.format(elem.tag_name)
                                break
                            except StaleElementReferenceException:
                                time.sleep(3.0)
                                intAttempts += 1
                                if intAttempts < settings.INT_MAX_ATTEMMPTS_FOR_STALEELEMENT:
                                    continue
                                else:
                                    raise
                            except Exception:
                                raise
                        

                        if elem.tag_name in ('a', 'link'):
                            strAttrHref = elem.get_attribute('href')
                            strLinkText = elem.text
                        elif elem.tag_name in ('img', 'script'):
                            strAttrHref = elem.get_attribute('src')
                            strAltText = '' if elem.get_attribute('alt') == None else elem.get_attribute('alt')

                        strAbsoluteURL = makeAbsoluteURL(strElementCheckingURL, strAttrHref)
                        if flagRunningMode == statics.RUNNING_MODE_URLLIST:
                            strInternalUrlChkBase = getNetLoc(strElementCheckingURL)

                        # if strAbsoluteURL is already checked or is external link, print message.
                        # if it is not checked yet, create message based on the response status and store it into q_checked_links.
                        if strAbsoluteURL in q_checked_links:
                            # already checkecd the status
                            checked_status_code = q_checked_links[strAbsoluteURL]

                            arrOutput = [unquote(strElementCheckingURL)
                                         , strLinkType
                                         , unquote(strAttrHref)
                                         , '(visited)'
                                         , checked_status_code]
                            
                            # increment counter based on the response status.
                            if checked_status_code >= 400:
                                countup_shared_variable(numInvalidLink)
                                writeOutMessageToTmpFile(os.path.join(link_check_worker.RESULT_DIRNAME, f_out_error), arrOutput)
                            elif checked_status_code < 0:
                                countup_shared_variable(numExceptions)
                                writeOutMessageToTmpFile(os.path.join(link_check_worker.RESULT_DIRNAME, f_out_exceptions), arrOutput)
                            else:
                                countup_shared_variable(numHealthyLink)
                                writeOutMessageToTmpFile(os.path.join(link_check_worker.RESULT_DIRNAME, f_out_ok), arrOutput)
                        elif not isInternalURL(strInternalUrlChkBase, strAttrHref):
                            countup_shared_variable(numExternalLinks)
                            
                            arrOutput = [unquote(strElementCheckingURL)
                                         , strLinkType
                                         , unquote(strAttrHref)
                                         , '(external link)'
                                         , ''
                                         , '']

                            writeOutMessageToTmpFile(os.path.join(link_check_worker.RESULT_DIRNAME, f_out_externalLinks), arrOutput)
                        else:
                            resp_elem = getResponse(strAbsoluteURL
                                                    , boolFollowRedirectIN
                                                    , basic_auth_id=strBasicAuthID
                                                    , basic_auth_pass=strBasicAuthPassword
                                                    , boolVerifySsl=boolVerifySSLCertIN)

                            arrOutput = [unquote(strElementCheckingURL)
                                         , strLinkType
                                         , unquote(strAttrHref)
                                         , resp_elem.reason
                                         , resp_elem.status_code
                                         , strAltText.replace("\r", '').replace("\n", '')
                                         , strLinkText.replace("\r", '').replace("\n", '') ]
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
                                       and isInternalURL(strInternalUrlChkBase, strAttrHref):
                                        q.append(strAbsoluteURL)
                                finally:
                                    lock.release()

                            # increment counter based on the response status.
                            if resp_elem.status_code >= 400:
                                countup_shared_variable(numInvalidLink)
                                writeOutMessageToTmpFile(os.path.join(link_check_worker.RESULT_DIRNAME, f_out_error), arrOutput)
                            elif resp_elem.status_code < 0:
                                countup_shared_variable(numExceptions)
                                writeOutMessageToTmpFile(os.path.join(link_check_worker.RESULT_DIRNAME, f_out_exceptions), arrOutput)
                            else:
                                countup_shared_variable(numHealthyLink)
                                writeOutMessageToTmpFile(os.path.join(link_check_worker.RESULT_DIRNAME, f_out_ok), arrOutput)
                    except StaleElementReferenceException as ex:
                        exc_type, exc_value, exc_traceback = sys.exc_info()
                        sam =  traceback.format_exception(exc_type, exc_value, exc_traceback)

                        arrOutput = [unquote(strElementCheckingURL)
                                     , f'Element: {str(elem)}'
                                     , ''
                                     , f'[Exception] @class : {ex.__class__.__name__}'
                                     , f'@in : {sys._getframe().f_code.co_name}'
                                     , f'Message : {repr(traceback.format_stack())}'
                                     , '' ]
                        countup_shared_variable(numExceptions)
                        writeOutMessageToTmpFile(os.path.join(link_check_worker.RESULT_DIRNAME, f_out_exceptions), arrOutput)
                    except Exception as ex:
                        exc_type, exc_value, exc_traceback = sys.exc_info()
                        sam =  traceback.format_exception(exc_type, exc_value, exc_traceback)
                        
                        arrOutput = [unquote(strElementCheckingURL)
                                     , f'Tag: "{elem.tag_name}"'
                                     , f"At attribute : {elem.get_attribute('innerHTML')}"
                                     , f'[Exception] @class : {ex.__class__.__name__ }'
                                     , f'@in : {sys._getframe().f_code.co_name},'
                                     , f'Message : {repr(traceback.format_stack())}'
                                     , '']
                        countup_shared_variable(numExceptions)
                        writeOutMessageToTmpFile(os.path.join(link_check_worker.RESULT_DIRNAME, f_out_exceptions), arrOutput)
                    # --- end of outer try in for elem in elems:
                #
                # --- enf of element cheging ---
                #

                
                arrConsoleLog = []
                for cl in driver.get_log('browser'):
                    
                    arrConsoleLog.append([cl['level']
                                          , cl['message']
                                          , cl['source']
                                          , datetime.datetime.fromtimestamp(float(cl['timestamp']/1000)).strftime('%Y%m%d-%H%M%S-%f')
                                          , strElementCheckingURL])
                    if cl['level'] == 'SEVERE':
                        countup_shared_variable(numConsoleSevere)
                    elif cl['level'] == 'WARNING':
                        countup_shared_variable(numConsoleWarn)
                if arrConsoleLog:
                    writeOutMessageToTmpFile(os.path.join(link_check_worker.RESULT_DIRNAME, f_out_consolelog), arrConsoleLog)
                arrConsoleLog = []

                
            except Exception as ex:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                sam =  traceback.format_exception(exc_type, exc_value, exc_traceback)

                arrOutput = [sys._getframe().f_code.co_name + ' is going to terminate due to unexpected exception at ' + datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f')
                             , ex.__class__.__name__
                             , str(traceback.format_tb(ex.__traceback__))
                             , 'strCurrentBrowsingURL : ' + strCurrentBrowsingURL
                             , ''
                             , ''
                             , '' ]
                countup_shared_variable(numCriticalExceptions)
                writeOutMsgToFile(os.path.join(link_check_worker.RESULT_DIRNAME, link_check_worker.FILE_CRITICALEXCEPTIONS_ALL), arrOutput, lock)
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

        arrOutput = [sys._getframe().f_code.co_name
                     , ex.__class__.__name__
                     , str(traceback.format_tb(ex.__traceback__))
                     , ''
                     , ''
                     , ''
                     , '' ]
        countup_shared_variable(numExceptions)
        writeOutMsgToFile(os.path.join(link_check_worker.RESULT_DIRNAME, link_check_worker.FILE_CRITICALEXCEPTIONS_ALL), arrOutput, lock)
        raise
    finally:
        driver.close()
        driver.quit()