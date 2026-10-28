"""Install only the IDOR lab's nftables table, leaving other tables alone."""
from pathlib import Path
import subprocess
import tempfile


NFT = '/usr/sbin/nft'
RULES = '/etc/idor-free-lab/server-acl.nft'
TABLE = ['table', 'inet', 'idor_server_acl']


def main():
    present = subprocess.run([NFT, 'list', *TABLE], check=False,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    rules = Path(RULES).read_text(encoding='utf-8')
    if present.returncode == 0:
        rules = 'delete table inet idor_server_acl\n' + rules
    with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8',
                                     prefix='idor-acl-', suffix='.nft',
                                     dir='/run', delete=True) as batch:
        batch.write(rules)
        batch.flush()
        subprocess.run([NFT, '-c', '-f', batch.name], check=True)
        subprocess.run([NFT, '-f', batch.name], check=True)


if __name__ == '__main__':
    main()
