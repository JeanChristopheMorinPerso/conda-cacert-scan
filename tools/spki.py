import csv, sys, subprocess
csv.field_size_limit(10**9)
def incident_revocation(r):
    date, reason = r['Date of Revocation'], r['RFC 5280 Revocation Reason Code'].lower().replace(' ', '')
    if 'cacompromise' in reason and date.startswith('2026 Oct'):
        return True
    return 'cessationofoperation' in reason and date.startswith('2026 Nov') and 'eMudhra' in r['CA Owner']
for r in csv.DictReader(open(sys.argv[1], newline='', encoding='utf-8')):
    if incident_revocation(r):
        pem = r['PEM Info'].strip("'")
        der = subprocess.run(['openssl','x509','-pubkey','-noout'], input=pem.encode(), capture_output=True).stdout
        h = subprocess.run('openssl pkey -pubin -outform DER | openssl dgst -sha256 -r', shell=True, input=der, capture_output=True).stdout.decode().split()[0]
        print(h, r['CA Owner'][:12], r['Certificate Subject Common Name'], '<-', r['Certificate Issuer Common Name'])
