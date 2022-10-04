def analyze_rf_result(self, fo, outfile, fe, errfile, remove_file=False):
    result_re = re.compile('^(\d+)\s+test.*(\d+)\s+passed.*(\d+)\s+failed', re.MULTILINE)
    errstr = ''
    nt = np = nf = 0
    errors = {}
    try:
        fo.flush()
        fe.flush()
        fo.close()
        fe.close()
        with open(outfile, 'r') as fd:
            output = fd.read()
            print('STDOUT:\n%s' % output)
        nt, np, nf = re.findall(result_re, output, )[0]
        case = None
        for line in output.split('\n'):
            if case:
                errors[case] = line.rstrip('  ')
                case = None
            if line.find('| FAIL |') > 0:
                case = line.replace('| FAIL |', '').replace('  ', '')
                continue
        with open(errfile, 'r') as fd:
            err_out = fd.read()
            print('STDERR:\n%s' % err_out)

    except IOError as estr:
        errstr = 'ERROR...unable to read output file "%s"\n%s' % (outfile, str(estr))
    except ValueError as estr:
        errstr = 'ERROR...output file "%s" is corrupted\n%s' % (outfile, str(estr))
    except Exception as estr:
        errstr = 'ERROR: unknown error %s' % str(estr)
    if len(errstr) > 0:
        logging.error(errstr)
    else:
        logging.debug('successfully parsed RF output file')
        if remove_file == True:
            os.unlink(fo)
            os.unlink(fe)
    if len(errors) > 0:
        errstr = ''.join('%s - %s\n' % (e, errors[e]) for e in errors)
        with open(errfile, 'r') as err:
            errstr += 'errorfile contents...\n%s' % err.read()
    return (errstr, (nt, np, nf))

