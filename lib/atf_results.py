#! /usr/bin/python

from lxml import etree
from lxml.builder import E
import os
from subprocess import call
import sys
from time import time
import logging

LOGPATH = '/var/www/cgi-bin/logs'
LOG = 'ATF.log'
logging.basicConfig(format='%(asctime)s %(process)d %(module)s [%(process)d]:%(funcName)s:%(lineno)d - %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p', filename='%s/%s' % (LOGPATH, LOG),
                    level=logging.DEBUG)

DOCROOT = '/var/www/html/htdocs'
SAMPLES_PER_PAGE = 20
PAGE_LIST_SIZE = 11


class Results:
    """
        Results class to scrape the iDevice test results from each of the XML files contained within each suite directory
        Arguments:  <test group>, <test suite>

    """

    def __init__(self, testgroup=None, suite='ALL', **kwrd):
        self.mlist = []
        self.verbose_result = {}
        self.terse_result = {'Passed': 0, 'Failed': 0, 'Disabled': 0, 'Total': 0}
        self.test_list = []
        if testgroup:
            self.mpath = mlist_path = '%s/tests.xml.master' % DOCROOT
            try:
                self.mlxml = mlxml = etree.parse(mlist_path)
            except:
                raise AssertionError, "Test Group %s doesn't exit" % testgroup
            if suite == 'ALL':
                self.mlxpath = mlxpath = 'group/[@name="%s"]' % testgroup
            else:
                self.mlxpath = mlxpath = '//group/[@name="%s"]/suite/[@name="%s"]' % (testgroup, suite)
            self.mlnode = mlnode = mlxml.find(mlxpath)
            if mlnode != None:
                for ste in mlnode.xpath('//testlist'):
                    pdir = ste.text.replace('_', ' ').split('/')
                    if pdir[0] == testgroup:
                        self.mlist.append(ste.text)

    def getResults(self):
        """
            Tabulates the results in both terse and verbose lists.  Terse list summarizes for upload to Graphite,
             verbose list provides pass/fail results for each test
        """
        for tlist in self.mlist:
            xml = etree.parse('%s/%s' % (DOCROOT, tlist))
            tests = xml.findall('//test')
            for test in tests:
                result = test.attrib['lastresult']
                try:
                    self.terse_result[result] += 1
                except KeyError:
                    self.terse_result[result] = 1
                self.terse_result['Total'] += 1
                self.verbose_result['%s/%s' % (os.path.dirname(tlist), test.attrib['name'])] = result
                self.test_list.append('%s/%s' % (os.path.dirname(tlist), test.attrib['name']))

    def processHyperscanResults(self, filestr='hyperscan_samples.csv', **opts):
	docpath = '%s/history/hyperscan' % DOCROOT	
        try:
            with open('%s/%s' % (docpath, filestr), 'r') as fr:
                samples = fr.readlines()
        except Exception as estr:
            print('Cannot read file %s...: %s' % (filestr, estr))

        allsamples = list(s.rstrip('\n').split(',') for s in samples)

        css = {'.heading': '{background-color: lightblue;font-family: Charcoal;font-size: 18px;}',
               '.evenrow': '{background-color: white;text-align: center;font-family: Courier;font-size: 16px;}',
               '.oddrow': '{background-color: lightgray;text-align: center;font-family: Courier;font-size: 16px;}',
               '.title': '{background-color: white;text-align: left; font-family: Charcoal; font-size: 18px;}',
               }

        html_style = ''.join('%s %s\n' % (cssname, css[cssname]) for cssname in css)
        http_equivs = {'Content-Type': 'text/html; charset=utf-8', 'Pragma': 'no-cache', 'Expires': '-1'}

        html_head = E.head(E.title("Hyperscan Performance History", html_class="title"))
        for http_equiv in http_equivs:
            meta = E.meta()
            meta.set('http-equiv', http_equiv)
            meta.set('content', http_equivs[http_equiv])

        html_head.append(E.meta(meta))
        html_head.append(E.style(html_style))

        html_body = E.body(E.h2("HyperScan Performance History", style="text-align:center"))
        body_table = E.table()
        body_table.set('width', '100%')
        body_table.set('border', '2')
        body_table.set('id', '1')

        col_header = E.tr(
            E.th('Date', onclick="sortTable(0)"),
            E.th('Attempt', onclick="sortTable(1)"),
            E.th('Type', onclick="sortTable(2)"),
            E.th('Procedure', onclick="sortTable(3)"),
            E.th('HWD', onclick="sortTable(4)"),
            E.th('Snort Version', onclick="sortTable(5)"),
            E.th('Initializing Snort', onclick="sortTable(6)"),
            E.th('Commencing Packet Processing', onclick="sortTable(7)"),
            E.th('Snort Start Time Duration', onclick="sortTable(8)"),
        )
        col_header.set('class', 'heading')
        body_table.append(col_header)

        count = 0
        for sample in allsamples:
            if (count % 2 == 0):
                val = 'evenrow'
            else:
                val = 'oddrow'
            count += 1
            col_val = E.tr(
                # html_class="%s" % val),
                E.td(sample[0]),
                E.td(sample[1]),
                E.td(sample[2]),
                E.td(sample[3]),
                E.td(sample[4]),
                E.td(sample[5]),
                E.td(sample[6]),
                E.td(sample[7]),
                E.td(sample[8]),
            )
            body_table.append(col_val)
        html_body.append(body_table)
        page = E.html(html_head, html_body)
        html_page = etree.tostring(page, pretty_print=True)
	htmlfile = '%s/results_summary.html' % docpath
        with open(htmlfile, 'w') as f:
            f.write(html_page)
	htmllink = 'https://' + htmlfile.replace('/var/www/html/htdocs',get_fqdn())
	return(htmllink)

    def processZeekData(self, filestr=None, docname=None,
                        **opts):  # this is to process iSensor release performance results
        try:
            with open('%s/%s' % (DOCROOT, filestr), 'r') as f:
                samples = f.readlines()
        except Exception as estr:
            raise AssertionError, 'Error reading sample file "%s" : %s' % (filestr, estr)
        # build unique lists based on model and snort version
        allsamples = list(s.rstrip('\n').split(',') for s in samples)
        snort_version = {}
        rulesets = {}

        http_equiv = {
            'Content-Type': 'text/html; charset=utf-8',
            'Pragma': 'no-cache',
            'Expires': '-1',
        }
        css = {
            '.heading': '{background-color: lightblue;font-family: Charcoal;font-size: 18px;}',
            '.component': '{background-color: lightblue;font-family: Charcoal;font-size: 18px;}',
            '.evenrow': '{background-color: white;text-align: center;font-family: Courier;font-size: 16px;}',
            '.legend': '{background-color: cyan;text-align: center;font-family: Sans Serif;font-size: 16px; font-weight: bold;}',
            '.oddrow': '{background-color: white;text-align: center;font-family: Courier;font-size: 16px;}',
            '.badvar': '{background-color: yellow;text-align: center;font-family: Courier;font-size: 16px;color: red; font-weight: bold;}',
            '.goodvar': '{background-color: white;text-align: center;font-family: Courier;font-size: 16px;color: black; font-weight: normal;}',
            '.note': '{background-color: lightblue;text-align: center; font-family: Charcoal; font-size: 16px; color: black;}',
            '.title': '{background-color: white;text-align: left; font-family: Charcoal; font-size: 18px;}',
            '.pagination': '{display: inline-block;}',
            '.pagination a': '{color: black;float: left;padding: 2px 8px;text-decoration: none;}',
            '.pagination a.active': '{background-color: #4CAF50;color: white;border: 1px solid #4CAF50;}',
            '.column-1': '{width: 22px;}',
        }
        style = ''.join('%s %s\n' % (cssname, css[cssname]) for cssname in css)
        with open('sorttab.js', 'r') as js:
            script = '\n//<![CDATA[\n%s\n//]]\>\n\t\t' % js.read()
        head = E.head(E.title(docname))
        for equiv in http_equiv:
            meta = E.meta()
            meta.set('http-equiv', equiv)
            meta.set('content', http_equiv[equiv])
            head.append(E.meta(meta))
        head.append(E.style(style))
        bitblaster = E.th('BitBlaster (FPS)', width='160px;')
        app_mix = E.th('App_Mix', width='420px;')

        column1 = '190px;'
        column2 = '80px;'
        column3 = '60px;'
        column4 = '80px;'
        column5 = '90px;'
        column6 = '250px;'
        column7 = '195px;'

        comphdr = E.tr(
            E.th(width='175px;'),
            E.th(width='75px;'),
            E.th(width='60px;'),
            E.th(width='75px;'),
            E.th(width='85px;'),
            E.th(width='230px;'),
            E.th('Session Sender', width='180px;'),
            bitblaster,
            app_mix,
            E.th('Zeek', width='195px;'),
            E.th(width='55px;'),
            border='0',
        )
        comphdr.set('class', 'component')
        header = E.tr(  # column headers
            E.th('Date / Time (UTC)', onclick="sortTable(0)", width=column1),
            E.th('Platform', onclick="sortTable(1)", width=column2),
            E.th('Speed', onclick="sortTable(2)", width=column3),
            E.th('P-FWD', onclick="sortTable(3)", width=column4),
            E.th('Version', onclick="sortTable(4)", width=column5),
            E.th('Ruleset', onclick="sortTable(5)", width=column6),
            E.th('Max Concurrent Sessions', onclick="sortTable(6)", width=column7),
            E.th('1024', onclick="sortTable(7)", width="80"),
            E.th('1500', onclick="sortTable(8)", width="80"),
            E.th('FPS (App_Mix)', onclick="sortTable(9"),
            E.th('Max Concurrent Connections', onclick="sortTable(10)"),
            E.th('Avg. Latency', onclick="sortTable(11)"),
            E.th('Zeek Version', onclick="sortTable(12)"),
            E.th('Zeek Pkts Proc', onclick="sortTable(13)"),
            E.th('Zeek Pkts Drop', onclick="sortTable(14)"),
            E.th('BP Bytes Tx', onclick="sortTable(15)"),
            E.th('Zeek Bytes Rx', onclick="sortTable(16)"),
            E.th('Zeek Byte Loss', onclick="sortTable(13)"),
            E.th('Result', onclick="sortTable(14)"),

        )
        header.set('class', 'heading')
        topheader = E.table(
            comphdr,
            border="0",
            width="100%")
        ptable = E.table(
            header,
            border='1',
            width='100%',
        )
        ptable.set('id', 'myTable')
        nlines = 0
        linecnt = 0
        page = 1
        logging.debug('%d records found in %s:\n%s' % (len(samples), filestr, str(samples)))
        for sample in sorted(samples, None, None, True):
            try:
                # None 0.0,0.0,0.0, 0.0,0.0,0.0,Unknown,0.00,FAILED
                date, model, speed, pfwd, version, ruleset, max_con_session, max_fps_1024, max_fps_1500, fps_app_mix, cc_total_app_mix, avg_lat, vzeek, pkts_proc, pkts_drop, bp_tx, zeek_rx, dratio, result = sample.split(
                    ',')
            # tput = '%6.2f' % float(tput_s)
            # lat = '%6.2f' % float(lat_s)
            except Exception as estr:
                raise AssertionError, 'Corruption sample record: sample=%s, error=%s' % (sample, estr)
            nlines += 1
            if nlines & 1 == 0:
                rowclass = 'evenrow'
            else:
                rowclass = 'oddrow'
            line = E.tr(
                E.td(date.replace('T', ' '), ),
                E.td(model),
                E.td(speed),
                E.td(pfwd),
                E.td(version),
                E.td(ruleset),
                E.td(max_con_session),
                E.td(max_fps_1024),
                E.td(max_fps_1500),
                E.td(fps_app_mix),
                E.td(cc_total_app_mix),
                E.td(avg_lat),
                E.td(vzeek),
                E.td(pkts_proc),
                E.td(pkts_drop),
                E.td(bp_tx),
                E.td(zeek_rx),
                E.td('%s%c' % (dratio, 0x25)),
                E.td(result),
            )
            line.set('class', rowclass)
            ptable.append(line)
            linecnt += 1
        note = E.td('Application Mix Flow Breakdown (greater than 1% of total)')
        note.set('colspan', '9')
        note.set('align', 'center')
        """
        mixtab = E.table(
                E.tr(note),
                E.tr(
                    E.td('Flows %'),
                    E.td('DNS'),
                    E.td('HTTP'),
                    E.td('HTTPS'),
                    E.td('iTunes'),
                    E.td('eBay'),
                    E.td('FTP'),
                    E.td('SMBv2'),
                    E.td(''),
                    ),
                E.tr(
                    E.td(''),
                    E.td('31.5'),
                    E.td('27.5'),
                    E.td('8.2'),
                    E.td('3.2'),
                    E.td('3.0'),
                    E.td('4.0'),
                    E.td('3.2'),
                    E.td(''),
                    ),
    
                E.tr(
                    E.td('Data %'),
                    E.td('HTTP'),
                    E.td('iTunes'),
                    E.td('YouTube'),
                    E.td('POP3'),
                    E.td('RTP'),
                    E.td('Facebook'),
                    E.td('HTTPS'),
                    E.td('Outlook Web'),
                    ),
                E.tr(
                    E.td(''),
                    E.td('63.8'),
                    E.td('10.7'),
                    E.td('5.7'),
                    E.td('5.0'),
                    E.td('4.0'),
                    E.td('3.2'),
                    E.td('1.67'),
                    E.td('3.2'),
                    )
    
    
                )
        mixtab.set('class','legend')
        mixtab.set('border','1')
        mixtab.set('width','50%')
        """

        note.set('class', 'note')
        body = E.body(E.h2(docname), topheader, ptable, E.script())
        # body = E.body(E.h2(docname), mixtab, topheader, ptable, E.script())

        html = E.html(head, body)
        htmlraw = etree.tostring(html, pretty_print=True).replace('MU', '&mu;')
        htmlstr = htmlraw[:htmlraw.find('script') - 1] + '<script>%s</script>\n\t</body>\n</html>' % script
        fname = filestr.replace('.csv', '')
        with open('%s/%s.html' % (DOCROOT, fname), 'w') as f:
            f.write(htmlstr)
        try:
            framework = etree.parse('%s/framework.xml' % DOCROOT)
            atfurl = framework.find('atf/url')
            html_doc = '%s.html' % fname
            history_url = atfurl.text.replace('admin/', html_doc)
        except:
            history_url = None
        return (history_url)

    def processPerformanceData(self, filestr='performance_metrics.csv', docname=None,**opts):
	# this is to process iSensor release performance results
	docpath = '%s/history/isensor_release' % DOCROOT
        try:
            with open('%s/%s' % (docpath, filestr), 'r') as f:
                samples = f.readlines()
        except Exception as estr:
            raise AssertionError, 'Error reading sample file "%s" : %s' % (filestr, estr)
        # build unique lists based on model and snort version
        allsamples = list(s.rstrip('\n').split(',') for s in samples)
        snort_version = {}
        rulesets = {}

        http_equiv = {
            'Content-Type': 'text/html; charset=utf-8',
            'Pragma': 'no-cache',
            'Expires': '-1',
        }
        css = {
            '.heading': '{background-color: lightblue;font-family: Charcoal;font-size: 18px;}',
            '.component': '{background-color: lightblue;font-family: Charcoal;font-size: 18px;}',
            '.evenrow': '{background-color: white;text-align: center;font-family: Courier;font-size: 16px;}',
            '.legend': '{background-color: cyan;text-align: center;font-family: Sans Serif;font-size: 16px; font-weight: bold;}',
            '.oddrow': '{background-color: white;text-align: center;font-family: Courier;font-size: 16px;}',
            '.badvar': '{background-color: yellow;text-align: center;font-family: Courier;font-size: 16px;color: red; font-weight: bold;}',
            '.goodvar': '{background-color: white;text-align: center;font-family: Courier;font-size: 16px;color: black; font-weight: normal;}',
            '.note': '{background-color: lightblue;text-align: center; font-family: Charcoal; font-size: 16px; color: black;}',
            '.title': '{background-color: white;text-align: left; font-family: Charcoal; font-size: 18px;}',
            '.pagination': '{display: inline-block;}',
            '.pagination a': '{color: black;float: left;padding: 2px 8px;text-decoration: none;}',
            '.pagination a.active': '{background-color: #4CAF50;color: white;border: 1px solid #4CAF50;}',

        }
        style = ''.join('%s %s\n' % (cssname, css[cssname]) for cssname in css)
        with open('sorttab.js', 'r') as js:
            script = '\n//<![CDATA[\n%s\n//]]\>\n\t\t' % js.read()
        head = E.head(E.title(docname))
        for equiv in http_equiv:
            meta = E.meta()
            meta.set('http-equiv', equiv)
            meta.set('content', http_equiv[equiv])
            head.append(E.meta(meta))
        head.append(E.style(style))
        bitblaster = E.th('BitBlaster (FPS)', colspan='2')
        app_mix = E.th('App_Mix', colspan='3')

        comphdr = E.tr(
            E.th(''),
            E.th(''),
            E.th(''),
            E.th(''),
            E.th(''),
            E.th(''),
            E.th('Session Sender'),
            bitblaster,
            app_mix,
        )
        comphdr.set('class', 'component')
        header = E.tr(  # column headers
            E.th('Date / Time (UTC)', onclick="sortTable(0)"),
            E.th('Platform', onclick="sortTable(1)"),
            E.th('Speed', onclick="sortTable(2)"),
            E.th('P-FWD', onclick="sortTable(3)"),
            E.th('Version', onclick="sortTable(4)"),
            E.th('Ruleset', onclick="sortTable(5)"),
            E.th('Max Concurrent Sessions', onclick="sortTable(6)"),
            E.th('1024', onclick="sortTable(7)"),
            E.th('1500', onclick="sortTable(8)"),
            E.th('FPS (App_Mix)', onclick="sortTable(9"),
            E.th('Max Concurrent Connections', onclick="sortTable(10)"),
            E.th('Avg. Latency', onclick="sortTable(11)"),
        )
        header.set('class', 'heading')
        topheader = E.table(
            comphdr,
            border="1",
            width="100%")
        ptable = E.table(
            header,
            border='1',
            width='100%',
        )
        ptable.set('id', 'myTable')
        nlines = 0
        linecnt = 0
        page = 1
        logging.debug('%d records found in %s:\n%s' % (len(samples), filestr, str(samples)))
        for sample in sorted(samples, None, None, True):
            try:
                date, model, speed, pfwd, version, ruleset, max_con_session, max_fps_1024, max_fps_1500, fps_app_mix, cc_total_app_mix, avg_lat = sample.split(
                    ',')
                # tput = '%6.2f' % float(tput_s)
                # lat = '%6.2f' % float(lat_s)
            except Exception as estr:
                raise AssertionError, 'Corruption sample record: sample=%s, error=%s' % (sample, estr)
            nlines += 1
            if nlines & 1 == 0:
                rowclass = 'evenrow'
            else:
                rowclass = 'oddrow'
            line = E.tr(
                E.td(date.replace('T', ' '), ),
                E.td(model),
                E.td(speed),
                E.td(pfwd),
                E.td(version),
                E.td(ruleset),
                E.td(max_con_session),
                E.td(max_fps_1024),
                E.td(max_fps_1500),
                E.td(fps_app_mix),
                E.td(cc_total_app_mix),
                E.td(avg_lat),
            )
            line.set('class', rowclass)
            ptable.append(line)
            linecnt += 1
        note = E.td('Application Mix Flow Breakdown (greater than 1% of total)')
        note.set('colspan', '9')
        note.set('align', 'center')
        mixtab = E.table(
            E.tr(note),
            E.tr(
                E.td('Flows %'),
                E.td('DNS'),
                E.td('HTTP'),
                E.td('HTTPS'),
                E.td('iTunes'),
                E.td('eBay'),
                E.td('FTP'),
                E.td('SMBv2'),
                E.td(''),
            ),
            E.tr(
                E.td(''),
                E.td('31.5'),
                E.td('27.5'),
                E.td('8.2'),
                E.td('3.2'),
                E.td('3.0'),
                E.td('4.0'),
                E.td('3.2'),
                E.td(''),
            ),

            E.tr(
                E.td('Data %'),
                E.td('HTTP'),
                E.td('iTunes'),
                E.td('YouTube'),
                E.td('POP3'),
                E.td('RTP'),
                E.td('Facebook'),
                E.td('HTTPS'),
                E.td('Outlook Web'),
            ),
            E.tr(
                E.td(''),
                E.td('63.8'),
                E.td('10.7'),
                E.td('5.7'),
                E.td('5.0'),
                E.td('4.0'),
                E.td('3.2'),
                E.td('1.67'),
                E.td('3.2'),
            )

        )
        mixtab.set('class', 'legend')
        mixtab.set('border', '1')
        mixtab.set('width', '50%')

        note.set('class', 'note')
        body = E.body(E.h2(docname), mixtab, topheader, ptable, E.script())

        html = E.html(head, body)
        htmlraw = etree.tostring(html, pretty_print=True).replace('MU', '&mu;')
        htmlstr = htmlraw[:htmlraw.find('script') - 1] + '<script>%s</script>\n\t</body>\n</html>' % script

        htmlfile = '%s/results_summary.html' % docpath
        with open(htmlfile, 'w') as f:
            f.write(htmlstr)
        htmllink = 'https://' + htmlfile.replace('/var/www/html/htdocs',get_fqdn())
        return(htmllink)



    def processPerformanceSamples(self, filestr=None, docname=None, **opts):  # this is to process ruleset test results
        from math import sqrt
	docpath = '%s/history/isensor_ruleset' % DOCROOT
        try:
            with open('%s/%s' % (docpath, filestr), 'r') as f:
                samples = f.readlines()
        except Exception as estr:
            raise AssertionError, 'Error reading sample file "%s" : %s' % (filestr, estr)
        # build unique lists based on model and snort version
        allsamples = list(s.rstrip('\n').split(',') for s in samples)
        snort_version = {}
        rulesets = {}
        for sample in allsamples:
            sversion = sample[2].rpartition('.')[0]
            if sversion not in snort_version:
                snort_version[sversion] = {'samples': [sample], 'mean': 0.0, 'std_dev': 0.0}
            else:
                snort_version[sversion]['samples'].append(sample)
        for version in snort_version:
            sample_size = len(snort_version[version]['samples'])
            assert sample_size > 0, 'Bad sample size for snort version %s' % version
            tputs = list(float(s[3]) for s in snort_version[version]['samples'])
            lat = list(float(s[4]) for s in snort_version[version]['samples'])
            mean = snort_version[version]['tput_mean'] = sum(tputs) / sample_size
            lmean = snort_version[version]['lat_mean'] = sum(lat) / sample_size
            variance = map(lambda x: (x - mean) ** 2, tputs)
            lvariance = map(lambda x: (x - lmean) ** 2, lat)
            average_variance = sum(variance) * 1.0 / len(variance)
            average_lat_variance = sum(lvariance) * 1.0 / len(lvariance)
            snort_version[version]['tput_std_dev'] = sqrt(average_variance)
            snort_version[version]['lat_std_dev'] = sqrt(average_lat_variance)

        http_equiv = {
            'Content-Type': 'text/html; charset=utf-8',
            'Pragma': 'no-cache',
            'Expires': '-1',
        }
        css = {
            '.heading': '{background-color: lightblue;font-family: Charcoal;font-size: 18px;}',
            '.evenrow': '{background-color: white;text-align: center;font-family: Courier;font-size: 16px;}',
            '.legend': '{background-color: cyan;text-align: center;font-family: Sans Serif;font-size: 16px; font-weight: bold;}',
            '.oddrow': '{background-color: white;text-align: center;font-family: Courier;font-size: 16px;}',
            '.badvar': '{background-color: yellow;text-align: center;font-family: Courier;font-size: 16px;color: red; font-weight: bold;}',
            '.goodvar': '{background-color: white;text-align: center;font-family: Courier;font-size: 16px;color: black; font-weight: normal;}',
            '.note': '{background-color: white;text-align: left; font-family: Charcoal; font-size: 16px; color: green;}',
            '.title': '{background-color: white;text-align: left; font-family: Charcoal; font-size: 18px;}',
            '.pagination': '{display: inline-block;}',
            '.pagination a': '{color: black;float: left;padding: 2px 8px;text-decoration: none;}',
            '.pagination a.active': '{background-color: #4CAF50;color: white;border: 1px solid #4CAF50;}',

        }
        style = ''.join('%s %s\n' % (cssname, css[cssname]) for cssname in css)
        with open('sorttab.js', 'r') as js:
            script = '\n//<![CDATA[\n%s\n//]]\>\n\t\t' % js.read()
        head = E.head(E.title(docname))
        for equiv in http_equiv:
            meta = E.meta()
            meta.set('http-equiv', equiv)
            meta.set('content', http_equiv[equiv])
            head.append(E.meta(meta))
        head.append(E.style(style))
        legend_h = E.tr(
            E.th(),
            E.th(),
            E.th('Throughput', colspan="2"),
            E.th('Latency', colspan="2")
        )
        legend_h.set('class', 'heading')
        legend_hdr = E.tr(
            E.th('Snort Version'),
            E.th('No. of Samples'),
            E.th('Mean (Mbps)'),
            E.th('Standard Deviation'),
            E.th('Mean (MUs)'),
            E.th('Standard Deviation'),
        )
        legend_hdr.set('class', 'heading')
        legend = E.table(legend_h, legend_hdr, border='1', width='75%')
        for version in sorted(snort_version.keys()):
            row = E.tr(
                E.td(version),
                E.td(str(len(snort_version[version]['samples']))),
                E.td('%6.2f' % snort_version[version]['tput_mean']),
                E.td('%6.2f' % snort_version[version]['tput_std_dev']),
                E.td('%6.2f' % snort_version[version]['lat_mean']),
                E.td('%6.2f' % snort_version[version]['lat_std_dev'])
            )
            row.set('class', 'legend')
            legend.append(row)

        header = E.tr(  # column headers
            E.th('Date / Time (UTC)', onclick="sortTable(0)"),
            E.th('Platform', onclick="sortTable(1)"),
            E.th('Snort Version', onclick="sortTable(2)"),
            E.th('Ruleset', onclick="sortTable(3)"),
            E.th('Throughput (Mbps)', onclick="sortTable(4)"),
            E.th('Variance', onclick="sortTable(5)"),
            E.th('Latency (MUs)', onclick="sortTable(6)"),
            E.th('Variance', onclick="sortTable(7)"),

        )
        header.set('class', 'heading')
        table = E.table(header,
                        border='1',
                        width='100%',
                        )
        table.set('id', 'myTable')
        ptable = E.table(header,
                         border='1',
                         width='100%',
                         )
        ptable.set('id', 'myTable')
        nlines = 0
        linecnt = 0
        page = 1

        for sample in sorted(samples, None, None, True):
            try:
                date, model, version, tput_s, lat_s = sample.split(',')
                tput = '%6.2f' % float(tput_s)
                lat = '%6.2f' % float(lat_s)
            except Exception as estr:
                raise AssertionError, 'Corruption sample record: sample=%s, error=%s' % (sample, estr)
            v = version.rpartition('.')
            try:
                rulesetv = v[2]
                snortversion = v[0]
            except:
                rulesetv = ''
                snortversion = ''
            tp_var = float(tput) - float(snort_version[snortversion]['tput_mean'])
            tp_color = 'badvar' if tp_var < 0 and abs(tp_var) > float(
                snort_version[snortversion]['tput_std_dev']) else 'goodvar'
            tp_cell = E.td('%6.2f' % tp_var)
            tp_cell.set('class', tp_color)
            lat_var = float(lat) - float(snort_version[snortversion]['lat_mean'])
            lat_color = 'badvar' if lat_var > 0 and abs(lat_var) > float(
                snort_version[snortversion]['lat_std_dev']) else 'goodvar'
            lat_cell = E.td('%6.2f' % lat_var)
            lat_cell.set('class', lat_color)
            nlines += 1
            if tp_color == 'red' or lat_color == 'red':
                rowclass = 'badvar'
            elif nlines & 1 == 0:
                rowclass = 'evenrow'
            else:
                rowclass = 'oddrow'
            line = E.tr(
                E.td(date.replace('T', ' '), ),
                E.td(model),
                E.td(snortversion),
                E.td(rulesetv),
                E.td(tput),
                tp_cell,
                E.td(lat),
                lat_cell,
            )
            line.set('class', rowclass)
            table.append(line)
            ptable.append(line)
            linecnt += 1
            if linecnt == SAMPLES_PER_PAGE:
                page = self.write_page(docname, filestr, page, 1 + (len(samples) / SAMPLES_PER_PAGE), head, ptable,
                                       legend, script)
                del ptable
                ptable = E.table(header, border='1', width='100%')
                ptable.set('id', 'myTable')
                linecnt = 0

        note = E.h4('Note: Throughput and Latency tests are run on the rulesets in the security category ONLY')
        note.set('class', 'note')
        body = E.body(E.h2(docname), note, legend, table, E.script())
        html = E.html(head, body)
        htmlraw = etree.tostring(html, pretty_print=True).replace('MU', '&mu;')
        htmlstr = htmlraw[:htmlraw.find('script') - 1] + '<script>%s</script>\n\t</body>\n</html>' % script

        htmlfile = '%s/performance_page.html' % docpath
        with open(htmlfile, 'w') as f:
            f.write(htmlstr)
        htmllink = 'https://' + htmlfile.replace('/var/www/html/htdocs',get_fqdn()).replace('.html','_1.html')
        return(htmllink)

    def write_page(self, docname, filestr, page, num_pages, head, table, legend, script):
	docpath = '%s/history/isensor_ruleset' % DOCROOT
        pagename_prefix = '%s_page' % filestr.replace('_samples', '').replace('.csv', '')
        note = E.h4('Note: Throughput and Latency tests are run on the rulesets in the security category ONLY')
        note.set('class', 'note')
        first_page = 1
        last_page = num_pages - 1
        page_start = int(page / PAGE_LIST_SIZE) * PAGE_LIST_SIZE
        page_end = page_start + PAGE_LIST_SIZE
        if page_end > num_pages:
            page_end = num_pages
            page_start = page_end - PAGE_LIST_SIZE
        if page_start < 1:
            page_start = 1

        htmlpage = E.p()
        previous_page = page - 1 if page - 1 > first_page else first_page
        div = E.div(
            E.a('&laquo;', href='%s_%s.html' % (pagename_prefix, first_page)),
            E.a('&lt;', href='%s_%s.html' % (pagename_prefix, previous_page))
        )
        div.set('class', 'pagination')
        for pagenum in range(page_start, page_end):
            if pagenum == num_pages:
                break;
            link = E.a(str(pagenum), href='%s_%s.html' % (pagename_prefix, pagenum))
            if pagenum == page:
                link.set('class', 'active')
            div.append(link)
        next_page = page + 1 if page + 1 <= last_page else last_page
        if page_end < num_pages:
            div.append(E.a('...&nbsp;&nbsp;&gt;', href='%s_%s.html' % (pagename_prefix, next_page)))
        else:
            div.append(E.a('&gt;', href='%s_%s.html' % (pagename_prefix, next_page)))

        div.append(E.a('&raquo;', href='%s_%s.html' % (pagename_prefix, last_page)))
        htmlpage.append(div)
        body = E.body(E.h2(docname), note, legend, table, htmlpage, E.script())
        html = E.html(head, body)
        htmlraw = etree.tostring(html, pretty_print=True).replace('MU', '&mu;').replace('amp;', '')
        htmlstr = htmlraw[:htmlraw.find('script') - 1] + '<script>%s</script>\n\t</body>\n</html>' % script
        with open('%s/%s_%s.html' % (docpath, pagename_prefix, page), 'w') as f:
            f.write(htmlstr)

        return page + 1

    def publishResult(self, environ, server, port, group):
        """
            Uses netcat to send results to Graphite servers
            Arguments: <environment=Agile|Pilot>, <server to send data>, <server port>, <automation group>
        """
        result_map = {'Passed': 'Pass', 'Failed': 'Fail', 'Total': 'Total'}  # Translate ATF speak to Graphite speak
        suite_map = {'iSensor Regression': 'TALON_ISENSOR_DEVICE', 'iSensor Ruleset Performance': 'CTUSignatures'}
        timestamp = int(time())
        for result in ('Passed', 'Failed', 'Total'):
            echostr = 'ec.sdlc.test.%s.%s.%s %d %d' % (
                environ.lower(), suite_map[group], result_map[result], self.terse_result[result], timestamp)
            cmdstr = 'echo %s | nc %s %d' % (echostr, server, port)
            call(cmdstr, shell=True)  # Call to netcat...comment for debugging
            print
            cmdstr  # uncomment for debugging


class NSXResults:

    def __init__(self, testgroup=None, suite='ALL', **kwrd):
        self.mlist = []
        self.verbose_result = {}
        self.terse_result = {'Passed': 0, 'Failed': 0, 'Disabled': 0, 'Total': 0}
        self.test_list = []
        if testgroup:
            self.mpath = mlist_path = '%s/tests.xml.master' % DOCROOT
            try:
                self.mlxml = mlxml = etree.parse(mlist_path)
            except:
                raise AssertionError, "Test Group %s doesn't exit" % testgroup
            if suite == 'ALL':
                self.mlxpath = mlxpath = 'group/[@name="%s"]' % testgroup
            else:
                self.mlxpath = mlxpath = '//group/[@name="%s"]/suite/[@name="%s"]' % (testgroup, suite)
            self.mlnode = mlnode = mlxml.find(mlxpath)
            if mlnode != None:
                for ste in mlnode.xpath('//testlist'):
                    pdir = ste.text.replace('_', ' ').split('/')
                    if pdir[0] == testgroup:
                        self.mlist.append(ste.text)

    def processPerformanceSamples(self, filestr=None, docname=None, **opts):  # this is to process ruleset test results
        from math import sqrt
        SAMPLES_PER_PAGE = 20
        logging.debug('filestr: %s' % filestr)
	docpath = '%s/history/isensor_ruleset' % DOCROOT
        try:
            with open('%s/%s' % (docpath,filestr), 'r') as f:
                samples = f.readlines()
        except Exception as estr:
            raise AssertionError, 'Error reading sample file "%s" : %s' % (filestr, estr)
        # build unique lists based on model and snort version
        allsamples = [s.rstrip('\n').split(',') for s in samples]
        nsx_version = {}
        rulesets = {}
        for sample in allsamples:
            if sample[0:0] == '':
                continue
            sversion = sample[1]
            if sversion not in nsx_version:
                nsx_version[sversion] = {'samples': [sample], 'mean': 0.0, 'std_dev': 0.0}
            else:
                nsx_version[sversion]['samples'].append(sample)
        for version in nsx_version:
            sample_size = len(nsx_version[version]['samples'])
            assert sample_size > 0, 'Bad sample size for snort version %s' % version
            tputs = list(float(s[3]) for s in nsx_version[version]['samples'])
            lat = list(float(s[4]) for s in nsx_version[version]['samples'])
            mean = nsx_version[version]['tput_mean'] = sum(tputs) / sample_size
            lmean = nsx_version[version]['lat_mean'] = sum(lat) / sample_size
            variance = map(lambda x: (x - mean) ** 2, tputs)
            lvariance = map(lambda x: (x - lmean) ** 2, lat)
            average_variance = sum(variance) * 1.0 / len(variance)
            average_lat_variance = sum(lvariance) * 1.0 / len(lvariance)
            nsx_version[version]['tput_std_dev'] = sqrt(average_variance)
            nsx_version[version]['lat_std_dev'] = sqrt(average_lat_variance)

        http_equiv = {
            'Content-Type': 'text/html; charset=utf-8',
            'Pragma': 'no-cache',
            'Expires': '-1',
        }
        css = {
            '.heading': '{background-color: lightblue;font-family: Charcoal;font-size: 18px;}',
            '.evenrow': '{background-color: white;text-align: center;font-family: Courier;font-size: 16px;}',
            '.legend': '{background-color: cyan;text-align: center;font-family: Sans Serif;font-size: 16px; font-weight: bold;}',
            '.oddrow': '{background-color: white;text-align: center;font-family: Courier;font-size: 16px;}',
            '.badvar': '{background-color: yellow;text-align: center;font-family: Courier;font-size: 16px;color: red; font-weight: bold;}',
            '.goodvar': '{background-color: white;text-align: center;font-family: Courier;font-size: 16px;color: green; font-weight: bold;}',
            '.note': '{background-color: white;text-align: left; font-family: Charcoal; font-size: 16px; color: green;}',
            '.title': '{background-color: white;text-align: left; font-family: Charcoal; font-size: 18px;}',
            '.pagination': '{display: inline-block;}',
            '.pagination a': '{color: black;float: left;padding: 2px 8px;text-decoration: none;}',
            '.pagination a.active': '{background-color: #4CAF50;color: white;border: 1px solid #4CAF50;}',

        }
        style = ''.join('%s %s\n' % (cssname, css[cssname]) for cssname in css)
        with open('sorttab.js', 'r') as js:
            script = '\n//<![CDATA[\n%s\n//]]\>\n\t\t' % js.read()
        head = E.head(E.title(docname))
        for equiv in http_equiv:
            meta = E.meta()
            meta.set('http-equiv', equiv)
            meta.set('content', http_equiv[equiv])
            head.append(E.meta(meta))
        head.append(E.style(style))
        legend_h = E.tr(
            E.th(),
            E.th(),
            E.th('Throughput', colspan="2"),
            E.th('Latency', colspan="2")
        )
        legend_h.set('class', 'heading')
        legend_hdr = E.tr(
            E.th('Node Version'),
            E.th('No. of Samples'),
            E.th('Mean (Mbps)'),
            E.th('Standard Deviation'),
            E.th('Mean (MUs)'),
            E.th('Standard Deviation'),
        )
        legend_hdr.set('class', 'heading')
        legend = E.table(legend_h, legend_hdr, border='1', width='75%')
        for version in sorted(nsx_version.keys()):
            row = E.tr(
                E.td(version),
                E.td(str(len(nsx_version[version]['samples']))),
                E.td('%6.2f' % nsx_version[version]['tput_mean']),
                E.td('%6.2f' % nsx_version[version]['tput_std_dev']),
                E.td('%6.2f' % nsx_version[version]['lat_mean']),
                E.td('%6.2f' % nsx_version[version]['lat_std_dev'])
            )
            row.set('class', 'legend')
            legend.append(row)

        header = E.tr(  # column headers
            E.th('Date / Time (UTC)', onclick="sortTable(0)"),
            E.th('Node Version', onclick="sortTable(1)"),
            E.th('Ruleset', onclick="sortTable(2)"),
            E.th('Throughput (Mbps)', onclick="sortTable(3)"),
            E.th('Variance', onclick="sortTable(4)"),
            E.th('Latency (MUs)', onclick="sortTable(5)"),
            E.th('Variance', onclick="sortTable(6)"),
            E.th('Result', onclick="sortTable(7)"),
        )
        header.set('class', 'heading')
        table = E.table(header,
                        border='1',
                        width='100%',
                        )
        table.set('id', 'xTable')
        nlines = 0
        linecnt = 0
        page = 1

        for sample in sorted(samples, None, None, True):
            try:
                date, nsxv, rulesetv, tput_s, lat_s, tresultstr = sample.split(',')
                tresult = tresultstr.rstrip('\n')
                tput = '%6.2f' % float(tput_s)
                lat = '%6.2f' % float(lat_s)
            except Exception as estr:
                raise AssertionError, 'Corruption sample record: sample=%s, error=%s' % (sample, estr)
            tp_var = float(tput) - float(nsx_version[nsxv]['tput_mean'])
            tp_color = 'badvar' if tp_var < 0 and abs(tp_var) > float(
                nsx_version[nsxv]['tput_std_dev']) else 'goodvar'
            tp_cell = E.td('%6.2f' % tp_var)
            tp_cell.set('class', tp_color)
            lat_var = float(lat) - float(nsx_version[nsxv]['lat_mean'])
            lat_color = 'badvar' if lat_var > 0 and abs(lat_var) > float(
                nsx_version[nsxv]['lat_std_dev']) else 'goodvar'
            lat_cell = E.td('%6.2f' % lat_var)
            lat_cell.set('class', lat_color)
            result_cell = E.td('%s' % tresult)
            result_color = 'badvar' if tresult.upper() == 'FAILED' else 'goodvar'
            result_cell.set('class', result_color)

            nlines += 1
            line = E.tr(
                E.td(date.replace('T', ' '), ),
                E.td(nsxv),
                E.td(rulesetv),
                E.td(tput),
                tp_cell,
                E.td(lat),
                lat_cell,
                result_cell,
            )
            # line.set('class', rowclass)
            table.append(line)
            linecnt += 1
        note = E.h4('Note: To Be added')
        note.set('class', 'note')
        body = E.body(E.h2(docname), note, legend, table, E.script())
        html = E.html(head, body)
        htmlraw = etree.tostring(html, pretty_print=True).replace('MU', '&mu;')
        logging.debug('htmlraw:\n%s' % htmlraw)
        htmlstr = htmlraw[:htmlraw.find('script') - 1] + '<script>%s</script>\n\t</body>\n</html>' % script
        logging.debug('htmlstr:\n%s' % htmlstr)
        fname = filestr.replace('_samples', '').replace('.csv', '')
        logging.debug('writing html to file: %s' % fname)
        with open('%s.html' % (fname), 'w') as f:
            f.write(htmlstr)
        try:
            framework = etree.parse('%s/framework.xml' % DOCROOT)
            atfurl = framework.find('atf/url')
            html_doc = '%s.html' % fname
            history_url = atfurl.text.replace('admin/', html_doc)
        except:
            history_url = None
        return history_url

    def write_page(self, docname, filestr, page, num_pages, head, table, legend, script):
        pagename_prefix = '%s_page' % filestr.replace('_samples', '').replace('.csv', '')
        note = E.h4('Note: Throughput and Latency tests are run on the rulesets in the security category ONLY')
        note.set('class', 'note')
        first_page = 1
        last_page = num_pages - 1
        page_start = int(page / PAGE_LIST_SIZE) * PAGE_LIST_SIZE
        page_end = page_start + PAGE_LIST_SIZE
        if page_end > num_pages:
            page_end = num_pages
            page_start = page_end - PAGE_LIST_SIZE
        if page_start < 1:
            page_start = 1

        htmlpage = E.p()
        previous_page = page - 1 if page - 1 > first_page else first_page
        div = E.div(
            E.a('&laquo;', href='%s_%s.html' % (pagename_prefix, first_page)),
            E.a('&lt;', href='%s_%s.html' % (pagename_prefix, previous_page))
        )
        div.set('class', 'pagination')
        for pagenum in range(page_start, page_end):
            if pagenum == num_pages:
                break;
            link = E.a(str(pagenum), href='%s_%s.html' % (pagename_prefix, pagenum))
            if pagenum == page:
                link.set('class', 'active')
            div.append(link)
        next_page = page + 1 if page + 1 <= last_page else last_page
        if page_end < num_pages:
            div.append(E.a('...&nbsp;&nbsp;&gt;', href='%s_%s.html' % (pagename_prefix, next_page)))
        else:
            div.append(E.a('&gt;', href='%s_%s.html' % (pagename_prefix, next_page)))

        div.append(E.a('&raquo;', href='%s_%s.html' % (pagename_prefix, last_page)))
        htmlpage.append(div)
        body = E.body(E.h2(docname), note, legend, table, htmlpage, E.script())
        html = E.html(head, body)
        htmlraw = etree.tostring(html, pretty_print=True).replace('MU', '&mu;').replace('amp;', '')
        htmlstr = htmlraw[:htmlraw.find('script') - 1] + '<script>%s</script>\n\t</body>\n</html>' % script
        with open('%s/%s_%s.html' % (self.docpath, pagename_prefix, page), 'w') as f:
            f.write(htmlstr)

        return (page + 1)

    def publishResult(self, environ, server, port, group):
        """
            Uses netcat to send results to Graphite servers
            Arguments: <environment=Agile|Pilot>, <server to send data>, <server port>, <automation group>
        """
        result_map = {'Passed': 'Pass', 'Failed': 'Fail', 'Total': 'Total'}  # Translate ATF speak to Graphite speak
        suite_map = {'iSensor Regression': 'TALON_ISENSOR_DEVICE', 'iSensor Ruleset Performance': 'CTUSignatures'}
        timestamp = int(time())
        for result in ('Passed', 'Failed', 'Total'):
            echostr = 'ec.sdlc.test.%s.%s.%s %d %d' % (
                environ.lower(), suite_map[group], result_map[result], self.terse_result[result], timestamp)
            cmdstr = 'echo %s | nc %s %d' % (echostr, server, port)
            call(cmdstr, shell=True)  # Call to netcat...comment for debugging
            #print(cmdstr)  # uncomment for debugging

class VRT_Results:
    """
        Results class to scrape the iDevice test results from each of the XML files contained within each suite directory
        Arguments:  <test group>, <test suite>

    """

    def __init__(self, testgroup, suite='ALL', **kwrd):
	self.docpath = '%s/history/vrt_ruleset' % DOCROOT

    def processPerformanceSamples(self, filestr='firepower_performance_samples.csv', **opts):
        from math import sqrt

        try:
            logging.debug('reading data input file %s/%s' % (self.docpath, filestr))
            print('reading data input file %s/%s' % (self.docpath, filestr))
            with open('%s/%s' % (self.docpath, filestr), 'r') as f:
                samples = f.readlines()
        except Exception as estr:
            raise AssertionError, 'Error reading sample file "%s" : %s' % (filestr, estr)
        # build unique lists based on model and snort version
        allsamples = list(s.rstrip('\n').split(',') for s in samples)
	print len(allsamples)
        logging.debug('found %s existing samples' % len(allsamples))
        vrt_models = {}
        rulesets = {}
        for sample in allsamples:
            logging.debug('processing sample %s' % sample)
	    logging.debug('sample: %s' % str(sample))
	    if len(sample) < 7 or len(sample[0]) == 0:
		continue
            model = sample[1]
            if model not in vrt_models:
                logging.info('found new model %s in samples' % model)
                vrt_models[model] = {'samples': [sample], 'mean': 0.0, 'std_dev': 0.0}
            else:
                vrt_models[model]['samples'].append(sample)
        for model in vrt_models:
            sample_size = len(vrt_models[model]['samples'])
            assert sample_size > 0, 'Bad sample size for model %s' % model
            tputs = list(float(s[4]) for s in vrt_models[model]['samples'])
            lat = list(float(s[5]) for s in vrt_models[model]['samples'])
            mean = vrt_models[model]['tput_mean'] = sum(tputs) / sample_size
            lmean = vrt_models[model]['lat_mean'] = sum(lat) / sample_size
            variance = map(lambda x: (x - mean) ** 2, tputs)
            lvariance = map(lambda x: (x - lmean) ** 2, lat)
            average_variance = sum(variance) * 1.0 / len(variance)
            average_lat_variance = sum(lvariance) * 1.0 / len(lvariance)
            vrt_models[model]['tput_std_dev'] = sqrt(average_variance)
            vrt_models[model]['lat_std_dev'] = sqrt(average_lat_variance)

        http_equiv = {
            'Content-Type': 'text/html; charset=utf-8',
            'Pragma': 'no-cache',
            'Expires': '-1',
        }
        css = {
            '.heading': '{background-color: lightblue;font-family: Charcoal;font-size: 18px;}',
            '.evenrow': '{background-color: white;text-align: center;font-family: Courier;font-size: 16px;}',
            '.legend': '{background-color: cyan;text-align: center;font-family: Sans Serif;font-size: 16px; font-weight: bold;}',
            '.oddrow': '{background-color: white;text-align: center;font-family: Courier;font-size: 16px;}',
            '.badvar': '{background-color: yellow;text-align: center;font-family: Courier;font-size: 16px;color: red; font-weight: bold;}',
            '.goodvar': '{background-color: white;text-align: center;font-family: Courier;font-size: 16px;color: black; font-weight: normal;}',
            '.note': '{background-color: white;text-align: left; font-family: Charcoal; font-size: 16px; color: green;}',
            '.title': '{background-color: white;text-align: left; font-family: Charcoal; font-size: 18px;}',
            '.pagination': '{display: inline-block;}',
            '.pagination a': '{color: black;float: left;padding: 2px 8px;text-decoration: none;}',
            '.pagination a.active': '{background-color: #4CAF50;color: white;border: 1px solid #4CAF50;}',
        }
        style = ''.join('%s %s\n' % (cssname, css[cssname]) for cssname in css)
        with open('sorttab.js', 'r') as js:
            script = '\n//<![CDATA[\n%s\n//]]\>\n\t\t' % js.read()
        head = E.head(E.title('VRT Ruleset Performance History'))
        for equiv in http_equiv:
            meta = E.meta()
            meta.set('http-equiv', equiv)
            meta.set('content', http_equiv[equiv])
            head.append(E.meta(meta))
        head.append(E.style(style))
        legend_h = E.tr(
            E.th(),
            E.th(),
            E.th('Throughput', colspan="2"),
            E.th('Latency', colspan="2")
        )
        legend_h.set('class', 'heading')
        legend_hdr = E.tr(
            E.th('Device Model'),
            E.th('No. of Samples'),
            E.th('Mean (Mbps)'),
            E.th('Standard Deviation'),
            E.th('Mean (MUs)'),
            E.th('Standard Deviation'),
        )
        legend_hdr.set('class', 'heading')
        legend = E.table(legend_h, legend_hdr, border='1', width='75%')
        for model in sorted(vrt_models.keys()):
            row = E.tr(
                E.td(model),
                E.td(str(len(vrt_models[model]['samples']))),
                E.td('%6.2f' % vrt_models[model]['tput_mean']),
                E.td('%6.2f' % vrt_models[model]['tput_std_dev']),
                E.td('%6.2f' % vrt_models[model]['lat_mean']),
                E.td('%6.2f' % vrt_models[model]['lat_std_dev'])
            )
            row.set('class', 'legend')
            legend.append(row)

        header = E.tr(  # column headers
            E.th('Date / Time (UTC)', onclick="sortTable(0)"),
            E.th('Device Model', onclick="sortTable(1)"),
            E.th('OS Version', onclick="sortTable(2)"),
            E.th('SRU Version', onclick="sortTable(3)"),
            E.th('CTU Ruleset', onclick="sortTable(4)"),
            E.th('Throughput (Mbps)', onclick="sortTable(5)"),
            E.th('Variance', onclick="sortTable(6)"),
            E.th('Latency (MUs)', onclick="sortTable(7)"),
            E.th('Variance', onclick="sortTable(8)"),
            E.th('Result', onclick="sortTable(9)"),

        )
        header.set('class', 'heading')
        table = E.table(header,
                        border='1',
                        width='100%',
                        )
        table.set('id', 'myTable')
        ptable = E.table(header,
                         border='1',
                         width='100%',
                         )
        ptable.set('id', 'myTable')
        nlines = 0
        linecnt = 0
        page = 1

        logging.info('processing %d samples' % len(samples))
        for sample in sorted(samples, None, None, True):
            try:
                #logging.debug('parsing sample: %s' % sample)
                dcol = sample.split(',')
                date, model, vrt_version, ruleset, tput_s, lat_s = dcol[0:6]
                try:
                    osversion = dcol[6]
                except IndexError:
                    osversion = 'Pre6.3'
                try:
                    result = dcol[7]
                except IndexError:
                    result = 'NA'
                tput = '%6.2f' % float(tput_s)
                lat = '%6.2f' % float(lat_s)

            except Exception as estr:
                raise AssertionError, 'Corruption sample record: sample=%s, error=%s' % (sample, estr)
            tp_var = float(tput) - float(vrt_models[model]['tput_mean'])
            tp_color = 'badvar' if tp_var < 0 and abs(tp_var) > float(
                vrt_models[model]['tput_std_dev']) else 'goodvar'
            tp_cell = E.td('%6.2f' % tp_var)
            tp_cell.set('class', tp_color)
            lat_var = float(lat) - float(vrt_models[model]['lat_mean'])
            lat_color = 'badvar' if lat_var > 0 and abs(lat_var) > float(
                vrt_models[model]['lat_std_dev']) else 'goodvar'
            lat_cell = E.td('%6.2f' % lat_var)
            lat_cell.set('class', lat_color)
            nlines += 1
            if tp_color == 'red' or lat_color == 'red':
                rowclass = 'badvar'
            elif nlines & 1 == 0:
                rowclass = 'evenrow'
            else:
                rowclass = 'oddrow'
            line = E.tr(
                E.td(date.replace('T', ' '), ),
                E.td(model),
                E.td(osversion),
                E.td(vrt_version),
                E.td(ruleset.replace('candidate-release-', '')),
                E.td(tput),
                tp_cell,
                E.td(lat),
                lat_cell,
                E.td(result),
            )
            line.set('class', rowclass)
            table.append(line)
            ptable.append(line)
            linecnt += 1
            if linecnt == SAMPLES_PER_PAGE:
                page = self.write_page('VRT Ruleset Performance History', filestr, page,
                                       1 + (len(samples) / SAMPLES_PER_PAGE), head, ptable, legend, script)
                del ptable
                ptable = E.table(header, border='1', width='100%')
                ptable.set('id', 'myTable')
                linecnt = 0
        if len(samples) < SAMPLES_PER_PAGE:
            page = self.write_page('VRT Ruleset Performance History', filestr, page,
                                   1 + (len(samples) / SAMPLES_PER_PAGE), head, ptable, legend, script)
        note = E.h4('Cisco Networks FirePOWER devices using Secureworks rulesets')
        note.set('class', 'note')
        body = E.body(E.h2('Ruleset Performance History'), note, legend, table, E.script())
        html = E.html(head, body)
        htmlraw = etree.tostring(html, pretty_print=True).replace('MU', '&mu;')
        htmlstr = htmlraw[:htmlraw.find('script') - 1] + '<script>%s</script>\n\t</body>\n</html>' % script
        #with open('%s/firepower_ruleset_performance.html' % self.docpath, 'w') as f:
        #    f.write(htmlstr)

        htmlfile = '%s/firepower_performance_page_1.html' % self.docpath
        #with open(htmlfile, 'w') as f:
        #    f.write(htmlstr)
        htmllink = 'https://' + htmlfile.replace('/var/www/html/htdocs',get_fqdn())
        return(htmllink)

    def write_page(self, docname, filestr, page, num_pages, head, table, legend, script):
        pagename_prefix = '%s_page' % filestr.replace('_samples', '').replace('.csv', '')
        note = E.h4('Cisco Networks FirePOWER devices using Secureworks rulesets')
        note.set('class', 'note')
        first_page = 1
        last_page = num_pages - 1
        page_start = int(page / PAGE_LIST_SIZE) * PAGE_LIST_SIZE
        page_end = page_start + PAGE_LIST_SIZE
        logging.info('docname: %s; filestr: %s; page: %s; num_pages: %s; table: %s  ' %(docname, filestr, page, num_pages, table))
        if page_end > num_pages:
            page_end = num_pages
            page_start = page_end - PAGE_LIST_SIZE
        if page_start < 1:
            page_start = 1

        htmlpage = E.p()
        previous_page = page - 1 if page - 1 > first_page else first_page
        div = E.div(
            E.a('&laquo;', href='%s_%s.html' % (pagename_prefix, first_page)),
            E.a('&lt;', href='%s_%s.html' % (pagename_prefix, previous_page))
        )
        div.set('class', 'pagination')
        for pagenum in range(page_start, page_end):
            if pagenum == num_pages:
                break
            link = E.a(str(pagenum), href='%s_%s.html' % (pagename_prefix, pagenum))
            if pagenum == page:
                link.set('class', 'active')
            div.append(link)
        next_page = page + 1 if page + 1 <= last_page else last_page
        if page_end < num_pages:
            div.append(E.a('...&nbsp;&nbsp;&gt;', href='%s_%s.html' % (pagename_prefix, next_page)))
        else:
            div.append(E.a('&gt;', href='%s_%s.html' % (pagename_prefix, next_page)))
        div.append(E.a('&gt;', href='%s_%s.html' % (pagename_prefix, next_page)))

        div.append(E.a('&raquo;', href='%s_%s.html' % (pagename_prefix, last_page)))
        htmlpage.append(div)
        body = E.body(E.h2(docname), note, legend, table, htmlpage, E.script())
        html = E.html(head, body)
        htmlraw = etree.tostring(html, pretty_print=True).replace('MU', '&mu;').replace('amp;', '')
        logging.debug('pagename_prefix: %s, page: %s' % (pagename_prefix, page))
        htmlstr = htmlraw[:htmlraw.find('script') - 1] + '<script>%s</script>\n\t</body>\n</html>' % script
        with open('%s/%s_%s.html' % (self.docpath, pagename_prefix, page), 'w') as f:
            f.write(htmlstr)

        return (page + 1)


class PAN_Results:
    """
        Results class to scrape the iDevice test results from each of the XML files contained within each suite directory
        Arguments:  <test group>, <test suite>

    """

    def __init__(self, testgroup, suite='ALL', **kwrd):
	self.docpath = '%s/history/pan_ruleset' % DOCROOT

    def processPerformanceSamples(self, filestr='pan_performance_samples.csv', **opts):
        from math import sqrt

        try:
            logging.debug('reading data input file %s' % filestr)
            with open('%s/%s' % (self.docpath, filestr), 'r') as f:
                samples = f.readlines()
        except Exception as estr:
            raise AssertionError, 'Error reading sample file "%s" : %s' % (filestr, estr)
        # build unique lists based on model and snort version
        allsamples = list(s.rstrip('\n').split(',') for s in samples)
        logging.debug('found %s existing samples' % len(allsamples))
        pan_models = {}
        rulesets = {}
        for sample in allsamples:
            # logging.debug('processing sample %s' % sample)
            model = sample[1]
            if model not in pan_models:
                # logging.info('found new model %s in samples' % model)
                pan_models[model] = {'samples': [sample], 'mean': 0.0, 'std_dev': 0.0}
            else:
                pan_models[model]['samples'].append(sample)
        for model in pan_models:
            sample_size = len(pan_models[model]['samples'])
            assert sample_size > 0, 'Bad sample size for model %s' % model
            tputs = list(float(s[4]) for s in pan_models[model]['samples'])
            lat = list(float(s[5]) for s in pan_models[model]['samples'])
            mean = pan_models[model]['tput_mean'] = sum(tputs) / sample_size
            lmean = pan_models[model]['lat_mean'] = sum(lat) / sample_size
            variance = map(lambda x: (x - mean) ** 2, tputs)
            lvariance = map(lambda x: (x - lmean) ** 2, lat)
            average_variance = sum(variance) * 1.0 / len(variance)
            average_lat_variance = sum(lvariance) * 1.0 / len(lvariance)
            pan_models[model]['tput_std_dev'] = sqrt(average_variance)
            pan_models[model]['lat_std_dev'] = sqrt(average_lat_variance)

        http_equiv = {
            'Content-Type': 'text/html; charset=utf-8',
            'Pragma': 'no-cache',
            'Expires': '-1',
        }
        css = {
            '.heading': '{background-color: lightblue;font-family: Charcoal;font-size: 18px;}',
            '.evenrow': '{background-color: white;text-align: center;font-family: Courier;font-size: 16px;}',
            '.legend': '{background-color: cyan;text-align: center;font-family: Sans Serif;font-size: 16px; font-weight: bold;}',
            '.oddrow': '{background-color: white;text-align: center;font-family: Courier;font-size: 16px;}',
            '.badvar': '{background-color: yellow;text-align: center;font-family: Courier;font-size: 16px;color: red; font-weight: bold;}',
            '.goodvar': '{background-color: white;text-align: center;font-family: Courier;font-size: 16px;color: black; font-weight: normal;}',
            '.note': '{background-color: white;text-align: left; font-family: Charcoal; font-size: 16px; color: green;}',
            '.title': '{background-color: white;text-align: left; font-family: Charcoal; font-size: 18px;}',
        }
        style = ''.join('%s %s\n' % (cssname, css[cssname]) for cssname in css)
        with open('sorttab.js', 'r') as js:
            script = '\n//<![CDATA[\n%s\n//]]\>\n\t\t' % js.read()
        head = E.head(E.title('PAN Ruleset Performance History'))
        for equiv in http_equiv:
            meta = E.meta()
            meta.set('http-equiv', equiv)
            meta.set('content', http_equiv[equiv])
            head.append(E.meta(meta))
        head.append(E.style(style))
        legend_h = E.tr(
            E.th(),
            E.th(),
            E.th('Throughput', colspan="2"),
            E.th('Latency', colspan="2")
        )
        legend_h.set('class', 'heading')
        legend_hdr = E.tr(
            E.th('PAN Model'),
            E.th('No. of Samples'),
            E.th('Mean (Mbps)'),
            E.th('Standard Deviation'),
            E.th('Mean (MUs)'),
            E.th('Standard Deviation'),
        )
        legend_hdr.set('class', 'heading')
        legend = E.table(legend_h, legend_hdr, border='1', width='75%')
        for model in sorted(pan_models.keys()):
            row = E.tr(
                E.td(model),
                E.td(str(len(pan_models[model]['samples']))),
                E.td('%6.2f' % pan_models[model]['tput_mean']),
                E.td('%6.2f' % pan_models[model]['tput_std_dev']),
                E.td('%6.2f' % pan_models[model]['lat_mean']),
                E.td('%6.2f' % pan_models[model]['lat_std_dev'])
            )
            row.set('class', 'legend')
            legend.append(row)

        header = E.tr(  # column headers
                        E.th('Date / Time (UTC)', onclick="sortTable(0)"),
                        E.th('Pan Model', onclick="sortTable(1)"),
                        E.th('PAN Version', onclick="sortTable(2)"),
                        E.th('PAN Ruleset', onclick="sortTable(3)"),
                        E.th('Throughput (Mbps)', onclick="sortTable(4)"),
                        E.th('Variance', onclick="sortTable(5)"),
                        E.th('Latency (MUs)', onclick="sortTable(6)"),
                        E.th('Variance', onclick="sortTable(7)"),

        )
        header.set('class', 'heading')
        table = E.table(header,
                        border='1',
                        width='100%',
        )
        table.set('id', 'myTable')
        nlines = 0
        logging.info('processing %d samples' % len(samples))
        for sample in sorted(samples, None, None, True):
            try:
                logging.debug('parsing sample: %s' % sample)
                date, model, pan_version, ruleset, tput_s, lat_s = sample.split(',')
                tput = '%6.2f' % float(tput_s)
                lat = '%6.2f' % float(lat_s)
            except Exception as estr:
                raise AssertionError, 'Corruption sample record: sample=%s, error=%s' % (sample, estr)
            tp_var = float(tput) - float(pan_models[model]['tput_mean'])
            tp_color = 'badvar' if tp_var < 0 and abs(tp_var) > float(
                pan_models[model]['tput_std_dev']) else 'goodvar'
            tp_cell = E.td('%6.2f' % tp_var)
            tp_cell.set('class', tp_color)
            lat_var = float(lat) - float(pan_models[model]['lat_mean'])
            lat_color = 'badvar' if lat_var > 0 and abs(lat_var) > float(
                pan_models[model]['lat_std_dev']) else 'goodvar'
            lat_cell = E.td('%6.2f' % lat_var)
            lat_cell.set('class', lat_color)
            nlines += 1
            if tp_color == 'red' or lat_color == 'red':
                rowclass = 'badvar'
            elif nlines & 1 == 0:
                rowclass = 'evenrow'
            else:
                rowclass = 'oddrow'
            line = E.tr(
                E.td(date.replace('T', ' '), ),
                E.td(model),
                E.td(pan_version),
                E.td(ruleset.replace('candidate-release-', '')),
                E.td(tput),
                tp_cell,
                E.td(lat),
                lat_cell,
            )
            line.set('class', rowclass)
            table.append(line)
        note = E.h4('Palo Alto Networks firewall devices using Secureworks rulesets')
        note.set('class', 'note')
        body = E.body(E.h2('Ruleset Performance History'), note, legend, table, E.script())
        html = E.html(head, body)
        htmlraw = etree.tostring(html, pretty_print=True).replace('MU', '&mu;')
        htmlstr = htmlraw[:htmlraw.find('script') - 1] + '<script>%s</script>\n\t</body>\n</html>' % script
	htmlfile = '%s/results_summary.html' % self.docpath
        with open(htmlfile, 'w') as f:
            f.write(htmlstr)
	htmllink = 'https://' + htmlfile.replace('/var/www/html/htdocs',get_fqdn())
	return(htmllink)

def get_fqdn():
	import re
        try:
                with open('/etc/hosts', 'r') as hosts:
                        fqdn_parse = re.findall('(a|p|r)(-atf.*net)', hosts.read(), re.MULTILINE)[0]
                        fqdn = fqdn_parse[0] + fqdn_parse[1]
                        logging.info('FQDN is %s' % fqdn)
			return(fqdn)
        except Exception as estr:
                logging.debug('failed to determine FQDN "%s"...exiting' % str(estr))
	return('')


# for execution from command line.  Web CGI will ultimately pull in the class and run automatically
if __name__ == '__main__':
	from optparse import OptionParser
	optprsr = OptionParser(usage="Usage %s <options>" % sys.argv[0])
	optprsr.add_option('-u', '--user', action='store', dest='user', default='None',
				help='ATF user (must be provsioned in the automation server)')
	optprsr.add_option('-i', '--isensor', action='store_true', dest='ruleset', default=False, help='iSensor ruleset')
	optprsr.add_option('-p', '--pan-ruleset', action='store_true', dest='pan', default=False, help='PAN ruleset')
	optprsr.add_option('-v', '--vrt-ruleset', action='store_true', dest='vrt', default=False, help='VRT ruleset')
	optprsr.add_option('-H', '--hyperscan', action='store_true', dest='hyper', default=False, help='Hyperscan result')
	optprsr.add_option('-r', '--release', action='store_true', dest='release', default=False, help='iSensor release')
	
	options, cliargs = optprsr.parse_args()
	if options.pan == True:
		R = PAN_Results('Ruleset_Performance')
		results_file = 'pan_performance_samples.csv'
		print(R.processPerformanceSamples(results_file))
	elif options.vrt == True:
		R = VRT_Results('Ruleset_Performance')
		results_file = 'firepower_performance_samples.csv'
		print(R.processPerformanceSamples(results_file))
	elif options.hyper == True:
		R = Results()
		results_file = 'hyperscan_samples.csv'
		print(R.processHyperscanResults(results_file))
	elif options.release == True:
		R = Results()
		results_file = 'performance_metrics.csv'
		docname = 'iSensor Release Performance History'
		print(R.processPerformanceData(results_file, docname))
        elif options.ruleset == True:
                R = Results()
                results_file = 'performance_samples.csv'
                docname = 'Ruleset Performance History'
                print(R.processPerformanceSamples(results_file, docname))
	results_lib = {
				'iSensor Results' 		: Results,
				'PAN Results'			: PAN_Results,
				'VRT Results'			: None,
				'Hyperscan Results'		: None,
				'iSensor Performance Results'	: None,
			}
