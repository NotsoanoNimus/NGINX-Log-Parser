#!/usr/bin/python3
#
# Compile yesterday's NGINX access.log request information into an HTML email notification.
#  The paramters in the USER-DEFINED PARAMETERS section below will allow you to adjust its behavior.
#
#
# REQUIREMENTS:
#   - An active NGINX instance.
#   - The following Linux/shell commands: whois, zcat, sendmail
#
# ASSUMPTIONS:
#   - The nginx logs are in the following format:
#       89.248.160.152 - - [07/Jan/2020:09:29:30 +0000] "GET /sites/wp-login.php HTTP/1.1" 404 564 "-" "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)" "-"
#   - Logs are rotated each day around 0400. This causes them to be named with the date of the the last logging.
#       So if a report is dated 20130505, the info actually ranges from 2013-05-04T04:00:00 to 2013-05-05T03:59:59
#   - All SMTP relaying and permissions are taken care of already. No need for credentials, special statements, etc.
#
# TODOS: None at this time.
#
#
import os, re, subprocess, random, tempfile, datetime, base64, hashlib, traceback
from datetime import date, timedelta


# SET "STATIC" GLOBAL VARIABLES.
# Get today's (and yesterday) date in 8-digit formatting (YYYYMMDD).
today_8 = (date.today()).strftime('%Y%m%d')
yesterday_8 = (date.today() - timedelta(days=1)).strftime('%Y%m%d')
# Get the current UNIX timestamp of the script.
scr_time_now = (datetime.datetime.now()).strftime('%s')
# Set up an empty dictionary object to 'cache' WHOIS query results.
who_dict = dict()


# SET USER-DEFINED PARAMETERS.
# Email-related parameters.
email = {
    'from' : 'NGINX Reports <no-reply@thestraightpath.email>',
    'to' : 'Notsoano Nimus <postmaster@thestraightpath.email>',
    'subject' : 'Daily NGINX Report: {0}'.format(yesterday_8)
}
# Set the location of the NGINX logs.
nginx_log_dir = "/var/log/nginx"
# Set to True to enable CSV reports of the logged actions as an attachment.
csv_reports = False


# Main function.
def main_func():
    # Check the existence of the target NGINX logfile.
    target_logfile = "{0}/access.log-{1}.gz".format(nginx_log_dir, today_8)
    send_log("Targeting log file: " + target_logfile)
    if not os.path.exists(target_logfile):
        send_log("ERROR: Log file doesn't exist. Notifying and terminating.")
        # If it wasn't found, complain!
        notif = build_message("The NGINX logfile at '{0}' could not be found!".format(target_logfile))
        send_message(notif)
        return
    # Decompress the NGINX file into a python variable.
    logfile_contents = decompress_log(target_logfile)
    # Create the message body.
    message_body, attach = interpret_nginx(logfile_contents)
    # Build the final notification.
    notif = build_message(message_body, attach)
    # Attempt to send the message out.
    send_message(notif)
    # Could just do this instead if feeling particularly evil:
    #  send_message(build_message(interpret_nginx(decompress_log(target_logfile))))


# Output a formatted message to STDOUT, which can be sent to a logfile.
def send_log(msg, err=None):
    if err is None:
        print("[ {0} ]> {1}".format((datetime.datetime.now()).strftime('%Y-%m-%dT%H:%M:%S'), msg))
    else:
        print("[ {0} ]> ERROR: {1}\n".format((datetime.datetime.now()).strftime('%Y-%m-%dT%H:%M:%S'), msg), err)


# Expand the NGINX logfile and decompress the contents.
def decompress_log(logfile):
    send_log("Using 'zcat' to decompress the target log.")
    logfile_perline = os.popen("zcat {0}".format(logfile)).readlines()
    return [x.strip() for x in logfile_perline]


# Interpret the decompressed content of the NGINX logs.
#  logfile_contents is an array containing the lines of the logfile.
def interpret_nginx(logfile_contents):
    # Sub-method to get the first matching item from a WHOIS query.
    #  Provides the ability to return a "fallback" string instead of the captured value.
    def get_who_info(whois_query_res, regexp, item_desc, csv=False):
        try:
            # Return lines matching the given regexp.
            retval_list = (list(filter(lambda z: re.search(regexp, z, flags=re.IGNORECASE), whois_query_res)))[0:]
            send_log("Parsing WHOIS result information:\n" + "\n".join(retval_list))
            if len(retval_list) <= 0:
                send_log("No match for item '{0}' was found.".format(item_desc))
                return "<em>NO {0}</em><br />-----<br />".format(item_desc.upper()), "{0}: No Results".format(item_desc)
            # Build the resulting HTML subsection.
            final_text = "<strong>{0}</strong>:<br />".format(item_desc)
            for idx, line in enumerate(retval_list):
                try:
                    final_text += "<strong>{0}</strong> - {1}<br />".format((idx+1), ((line.strip())[len(regexp):]).strip())
                except:
                    continue
            final_text += "-----<br />"
            plain_text = line.strip().replace(',', '')
            return final_text, plain_text
        except Exception as e:
            send_log("No match for item " + item_desc + ".", e)
            print(traceback.format_exc())
            return "<em>NO {0}</em><br />-----<br />".format(item_desc.upper()), "{0}: No Results".format(item_desc)

    # Another sub-method to generate fallback text for variables that don't come out of split lines properly.
    #  Check pieces of interest against a regex.
    #  If they don't match, try to find the regex within the entirety of the log-line.
    #  If both of those processes fail, simply set the value to "NONE".
    # NOTE: regexp is run against the 'match' command, meaning this is expecting the regex to cover
    #        the ENTIRE variable value.
    def check_split_item(assumed_content, logline, regexp):
        retval = assumed_content
        if bool(re.match(regexp, assumed_content)) is False:
            retval = re.search(regexp, logline)
            if retval.group(0) is None:
                retval = "NONE"
            else:
                retval = retval.group(0)
        return retval

    # Sub-method that gets all necessary information from a single NGINX log line.
    def split_log_line(log_line):
        # Split the log line by space characters ' '.
        try:
            x = log_line.split(' ', 5)
        except Exception as e:
            send_log("WARNING: Unable to split log line: {0}".format(log_line), e)
            return None, None, None, None, None
        # Use the sub-routine to ensure the variables at least have some kind of information.
        #  This is in case the split contains extra spaces than expected from the log format.
        ll_date = check_split_item(x[3][1:], log_line, r'[0-9]{2}\/[a-zA-Z]{3}\/[0-9]{4}(:[0-9]{2}){3}')
        ll_src = check_split_item(x[0], log_line, r'(([0-9]{1,3}(\.[0-9]{1,3}){3})|[0-9a-fA-F\:]+)')
        ### On second thought, this should stay as the last item in the split. Even if there were more spaces than
        ###  expected before this point, this will still just include 'the rest of it' so it doesn't matter.
        ll_req = x[5]   #check_split_item(x[5], log_line, r'')
        # WHOIS Section
        try:
            send_log("Running WHOIS query on address {0}.".format(ll_src))
            # If the WHOIS information is already present for this source, do not run another query.
            who = ""
            if ll_src in list(who_dict.keys()):
                send_log("\tSource {0} already queried. Using cached value.".format(ll_src))
                who = who_dict.get(ll_src)
            else:
                # Use the Linux 'whois' command to fetch WHOIS info, split it line-by-line, and strip extra whitespace.
                send_log("\tNew address {0}, running WHOIS DNS query.".format(ll_src))
                who = str(subprocess.check_output("whois {0} -H".format(ll_src), shell=True), 'latin-1')
                who = who.split('\n')
                who = [x.strip() for x in who]
                # Add the information to the caching dictionary.
                who_dict[ll_src] = who
        except Exception as e:
            send_log("WARNING: Failed to get WHOIS information for: {0}\n".format(ll_src), e)
            who = ("No results")
        # Scaffold an empty string to append to.
        whois_result = ""
        whois_csv = ""
        # Define the items to extract from the whois query results with the given regexp.
        whois_greps = (
            (r'owner:', 'Block Owner'),
            (r'orgname:', 'Org Name'),
            (r'netname:', 'Net Name'),
            (r'descr:', 'Description'),
        )
        # For each item in the above tuple, call another sub-method to extract the desired information.
        #  The result of the sub-method is HTML that altogether form PART OF the final table for this log entry.
        send_log("Getting desired 'whois_greps' information from the WHOIS result.")
        for reg, desc in whois_greps:
            who_html, who_csv = get_who_info(who, reg, desc)
            whois_result += who_html
            whois_csv += "{0}; ".format(who_csv.replace(';', ''))
        # If the whois_result variable is still blank, just mention that nothing was found.
        #  Due to the "fallback" in the get_who_info method, this should never happen.
        if whois_result == "":
            whois_result = "No Results"
        # Finally, return all important strings.
        return (ll_date, ll_src, ll_req, whois_result, whois_csv)

    # Set up a blank string for the message body HTML content.
    html_results = ""
    # Set up the initial CSV content.
    csv_content = "SEP=,\n" + '"Date","Source","Request","Request Info"'
    # MAIN FOR LOOP for parsing the log's content.
    send_log("Starting line-by-line transactions...")
    for line in logfile_contents:
        # For each log line in the contents array, extract the beneficial pieces.
        line_date, line_source, line_req, line_who, line_who_csv = split_log_line(line)
        send_log("Line Information:\n\tDate: {0}\n\tSource: {1}\n\tRequest Info: {2}\n\tWHOIS HTML: {3}".format(
            line_date, line_source, line_req, line_who))
        send_log("\tPlain-text CSV WHOIS content: {0}".format(line_who_csv))
        # If the source of the line comes back as null, don't log this line.
        if line_source is None:
            send_log("WARNING: Empty SOURCE field, skipping.")
            continue
        # Build onto the HTML and CSV contents.
        html_results += (
            "\r\n<tr><td>{0}</td><td><span style='color:#d67600;font-weight:bold;'>{1}</span>" +
            "</td><td style='max-width:260px;'>{2}</td><td>{3}</td></tr>"
        ).format(line_date, line_source, line_req, line_who)
        csv_content  += "\n\"{0}\",\"{1}\",\"{2}\",\"{3}\"".format(
            line_date.replace(',', ''), line_source.replace(',', ''),
            line_req.replace(',', ''), line_who_csv.replace(',', ''))
    # Only send a notification if the html_results variable has been populated.
    if html_results != "":
        send_log("Results were extracted. Building the HTML notification.")
        # Set up formatting and prepare the CSV attachment, in case it's being attached.
        #   NOTE: Because of CSS formatting, can't use the formatting function for strings here.
        return_val = (
            "<html><head><style>p { font-size:11px; }" +
            " th { background-color: #EDEDED; font-size:14px; font-family:verdana; }" +
            " td,tr { max-width:200px; word-wrap:break-word; font-size:12px; font-family:monospace; padding:2px 10px; }" +
            " tr:nth-child(even) { background-color: #FFF } tr:nth-child(odd) { background-color: #CCC }" +
            "</style></head><body><h4>NGINX Events, Yesterday (" + yesterday_8 + ")</h4>" + 
            "<table><th>Date</th><th>Source</th><th>Request</th><th>Request Info</th>" + 
            html_results + "</table></body></html>"
        )
        # Encode the CSV in base64.
        b64_csvBytes = base64.b64encode(csv_content.encode('utf-8'))
        # Get the result as a UTF-8 string.
        b64_csv = str(b64_csvBytes, 'utf-8')
        # Set up the 'csv_attachment' variable with the appropriate MIME headers and base64 content.
        csv_attachment = (
            "Content-Description: NGINX_{0}.csv\r\n" +
            "Content-Disposition: attachment; filename=\"NGINX_{0}.csv\";\r\n" +
            "    creation-date=\"{1}\";\r\n" +
            "Content-Type: text/plain; name=\"NGINX_{0}.csv\"\r\n" +
            "Content-Transfer-Encoding: base64\r\n\r\n" +
            "{2}\r\n"
        ).format(scr_time_now, (datetime.datetime.now()).strftime('%s'), b64_csv)
        # If CSVs are enabled, return the attachment with the content. Otherwise, don't.
        if csv_reports is True:
            return return_val, csv_attachment
        else:
            return return_val, None
    else:
        return "There were no lines to parse within the target logfile."


# Write the body message to a tempfile and return the tempfile name.
def build_message(msg_body, attachment=None):
    # Set up the initial email contents.
    formatted_msgid_date = (datetime.datetime.now()).strftime('%Y%m%d%H%M%S') + '-0500.'
    email_base = "From: {0}\r\nTo: {1}\r\nSubject: {2}\r\nMessage-Id: <{3}{4}@thestraightpath.email>\r\nMIME-Version: 1.0\r\n".format(
        email.get('from'), email.get('to'), email.get('subject'), formatted_msgid_date, random.randint(10000,99999)
    )
    # Make the tempfile.
    fd, tmp_name = tempfile.mkstemp()
    try:
        with os.fdopen(fd, 'w') as tmpfile:
            if attachment is None:
                # No attachment, just a plain message.
                email_base += "Content-Type: text/html; charset=\"us-ascii\"\r\n\r\n"
                email_base += msg_body
            else:
                mime_boundary = "tspnginx__{0}".format(hashlib.md5(str(random.randint(1000,999999)).encode('utf-8')).hexdigest())
                email_base += (
                    "Content-Type: multipart/mixed; boundary=\"{0}\"\r\n\r\n" + 
                    "--{0}\r\nContent-Type: text/html; charset=\"utf-8\"\r\n\r\n{1}\r\n\r\n--{0}\r\n{2}\r\n\r\n--{0}--"
                ).format(mime_boundary, msg_body, attachment)
            # Write the email to the tempfile.                
            tmpfile.write(email_base)
        # Since all went well, return the file path.
        return tmp_name
    except Exception as e:
        send_log("There was an issue writing to the file: ", e)
        os.remove(tmp_name)
        return None


# Send an email to the destination with the given string or content.
def send_message(msg_body_tempfile):
    send_log("Attempting to send message content to 'sendmail'.")
    try:
        # Input the file into sendmail to dispatch the email.
        os.system("sendmail -t <{0}".format(msg_body_tempfile))
    except Exception as e:
        send_log("There was a problem piping the email file through sendmail!", e)
    finally:
        os.remove(msg_body_tempfile)


# Call the main method and exit.
if __name__ == "__main__":
    # Print out starting configuration information.
    send_log("\n\n========== RUNNING NGINX REPORT ==========")
    send_log("PARAMS:\nEMAIL\n\tFrom: {0}\n\tTo: {1}\n\tSubject: {2}\nLog Directory: {3}\nCSV? {4}\n".format(
        email.get('from'), email.get('to'), email.get('subject'), nginx_log_dir, csv_reports))
    # Run the main function.
    main_func()
    # Output terminating log information.
    send_log("========== END ==========\n\n")
