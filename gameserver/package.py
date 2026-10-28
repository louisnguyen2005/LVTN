"""Build a source-only CyberRangeCZ ZIP, excluding allocation secrets and run data."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
from zipfile import ZipFile,ZIP_DEFLATED
from .deployment import ROOT
from .definition import rendered_files

ROOT_FILES={'deployment.json','topology.yml','training-definition.json','README.md','.gitignore',
            'requirements-dev.txt','requirements-runner.txt','Configure-Deployment.ps1','Apply-GatewayFirewall.ps1'}
SOURCE_DIRS={'app','checker','gameserver','provisioning','tests','CyberRangeCZ-Windows-Gateway','docs','.github'}
EXTENSIONS={'.py','.json','.html','.md','.txt','.ps1','.yml','.yaml','.j2','.service','.nft','.docx','.sql'}
ENV_FILES={'CyberRangeCZ-Windows-Gateway/config.json','checker/web_targets_gateway.json',
           'checker/credentials.json','gameserver/services.json','gameserver/local.json'}
PRIVATE=re.compile(rb'-----BEGIN (?:OPENSSH |RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----')


def source_files(root):
    root=Path(root).resolve()
    for file in sorted(root.rglob('*')):
        relative=file.relative_to(root)
        if any(p.startswith('runtime') or p in ('.git','__pycache__','.venv','node_modules','logs','results','artifacts') for p in relative.parts):continue
        if relative.as_posix() in ENV_FILES:continue
        if file.is_symlink():raise ValueError('Symlinks are not included in upload source')
        if not file.is_file():continue
        if relative.parts[0] not in SOURCE_DIRS and relative.as_posix() not in ROOT_FILES:continue
        if file.suffix not in EXTENSIONS and relative.as_posix() not in ROOT_FILES:continue
        if file.suffix=='.docx' and file.name!='Huong-dan-van-hanh-NOVA-MART-CTF.docx':continue
        if not file.resolve().is_relative_to(root):raise ValueError('Source file escapes package root')
        yield relative,file


def build(output,root=ROOT):
    root=Path(root).resolve();output=Path(output).resolve()
    for relative,content in rendered_files(root/'deployment.json').items():
        if not (root/relative).exists() or (root/relative).read_text(encoding='utf-8')!=content:
            raise ValueError('Generated file is stale: '+relative+'; run gameserver.definition --write')
    files=[]
    for relative,path in source_files(root):
        raw=path.read_bytes()
        if PRIVATE.search(raw):raise ValueError('Private key material in source: '+relative.as_posix())
        if path.suffix=='.py':ast.parse(raw,filename=str(relative))
        if path.suffix=='.json':
            parsed=json.loads(raw)
            if isinstance(parsed,dict) and any(k in parsed for k in ('admin_token','checker_token')):
                raise ValueError('Organizer token config is not allowed in upload source')
        files.append((relative,raw))
    names={relative.as_posix() for relative,_ in files}
    required={'topology.yml','provisioning/playbook.yml','provisioning/service-instance.yml','deployment.json',
              'gameserver/schema.sql','gameserver/scoreboard.html','app/portal.py','app/portal.html',
              'gameserver/monitor.html','app/service.py','app/shop.py','app/shop.html','checker/shop.py',
              'provisioning/templates/lab-addresses.j2','provisioning/templates/team-restarts.j2'}
    if not required<=names:
        raise ValueError('Missing required CyberRangeCZ source files')
    output.parent.mkdir(parents=True,exist_ok=True)
    temp=output.with_suffix(output.suffix+'.tmp')
    try:
        with ZipFile(temp,'w',ZIP_DEFLATED) as archive:
            for relative,raw in files:archive.writestr(relative.as_posix(),raw)
        temp.replace(output)
    finally:
        if temp.exists():temp.unlink()
    sha=hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_suffix(output.suffix+'.sha256').write_text(sha+'  '+output.name+'\n',encoding='ascii')
    return {'archive':str(output),'files':len(files),'sha256':sha}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    args=p.parse_args()
    try:print(json.dumps(build(args.output),indent=2))
    except (ValueError,OSError,SyntaxError) as exc:p.error(str(exc))


if __name__=='__main__':main()
