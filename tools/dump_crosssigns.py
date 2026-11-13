import csv, sys, os
csv.field_size_limit(10**9)
def incident_revocation(r):
    date, reason = r['Date of Revocation'], r['RFC 5280 Revocation Reason Code'].lower().replace(' ', '')
    if 'cacompromise' in reason and date.startswith('2026 Oct'):
        return True
    return 'cessationofoperation' in reason and date.startswith('2026 Nov') and 'eMudhra' in r['CA Owner']
for r in csv.DictReader(open(sys.argv[1], newline='', encoding='utf-8')):
    if incident_revocation(r):
        n = ('sectigo-' if r['CA Owner']=='Sectigo' else 'emudhra-') + r['Certificate Subject Common Name'].replace(' ','_')
        open(os.path.join(sys.argv[2], n+'.pem'),'w').write(r['PEM Info'].strip("'")+'\n')
