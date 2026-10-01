"""Fail if a UI key is missing from the compiled translation catalog."""
from pathlib import Path
import json,re

root=Path(__file__).resolve().parents[1]
literal=r'"(?:\\.|[^"\\])*"'
catalog={}
for key,value in re.findall(r'^\s*('+literal+r'):\s*('+literal+r'),$',(root/'Translations.swift').read_text(),re.M):
    key,value=json.loads(key),json.loads(value)
    assert key not in catalog, 'Duplicate translation key: '+key
    assert value and sorted(re.findall(r'\{\d+\}',key))==sorted(re.findall(r'\{\d+\}',value)),key
    catalog[key]=value
assert len(catalog)>300
count=0
for source in root.glob('*.swift'):
    if source.name in {'Translations.swift','Localization.swift'} or 'Tests' in source.name:continue
    text=source.read_text()
    assert not re.search('[А-Яа-яЁё]',text), 'Unlocalized Russian in '+source.name
    for key in re.findall(r'\bL\(('+literal+r')',text):
        key=json.loads(key)
        assert key in catalog, source.name+': missing translation for '+key
        count+=1
print('PASS:',count,'localized UI calls;',len(catalog),'complete English/Russian catalog entries')
