"""Historical recipe regression fixtures; not the Mantis service end-to-end test."""
import difflib
import json
import pathlib
import shutil
import subprocess
import sys
import urllib.request
import xml.etree.ElementTree as ET

SCENARIOS = {
    'jackson': ('com.fasterxml.jackson.core:jackson-databind', 'CVE-2020-36518', '2.9.8', '2.13.5'),
    'boot-managed': ('org.springframework:spring-webflux', 'CVE-2024-38816', '6.1.12', '6.1.13'),
}
name = sys.argv[1]
package, cve, before_version, after_version = SCENARIOS[name]
out = pathlib.Path('regression-output').resolve()
out.mkdir(exist_ok=True)
work = out / name
work.mkdir()  # Never reuse a dirty fixture.
ns = {'m': 'http://maven.apache.org/POM/4.0.0'}

def write(relative, content):
    path = work / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding='utf-8')

def mvn(label, *args):
    command = ['mvn', '-B', '-ntp', *args]
    with (out / (name + '-' + label + '.log')).open('w', encoding='utf-8') as log:
        result = subprocess.run(command, cwd=work, stdout=log, stderr=subprocess.STDOUT, timeout=600)
    if result.returncode:
        print((out / (name + '-' + label + '.log')).read_text()[-16000:])
        raise RuntimeError(f'{label} failed: exit {result.returncode}')

def scan(version, label, expected):
    request = urllib.request.Request('https://api.osv.dev/v1/query',
        data=json.dumps({'package': {'ecosystem': 'Maven', 'name': package}, 'version': version}).encode(),
        headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=60) as response:
        body = json.load(response)
    (out / f'{name}-{label}-osv.json').write_text(json.dumps(body, indent=2))
    findings = body.get('vulns', [])
    present = any(cve == item['id'] or cve in item.get('aliases', []) for item in findings)
    if present != expected:
        raise AssertionError(f'{cve}: expected present={expected} for resolved {version}, got {present}')
    return {'version': version, 'target_advisory_present': present, 'total_advisories': len(findings)}

def resolved(label, expected):
    mvn(label, 'org.apache.maven.plugins:maven-dependency-plugin:3.8.1:tree',
        f'-Dincludes={package}', '-DoutputFile=resolved.txt')
    tree = (work / 'resolved.txt').read_text()
    (out / f'{name}-{label}.txt').write_text(tree)
    matches = [line.strip().split(package + ':', 1)[1].split(':')[1]
               for line in tree.splitlines() if package + ':' in line]
    if matches != [expected]:
        raise AssertionError(f'Unexpected resolved versions: {matches}, expected {expected}')
    return matches[0]

parent = ''
if name == 'boot-managed':
    parent = '<parent><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-parent</artifactId><version>3.3.3</version><relativePath/></parent>'
    dependencies = '<dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-webflux</artifactId></dependency>'
    recipe = '''  - org.openrewrite.maven.UpgradeParentVersion:
      groupId: org.springframework.boot
      artifactId: spring-boot-starter-parent
      newVersion: 3.3.4
'''
    test = '''package regression;
import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.Configuration;
import static org.junit.jupiter.api.Assertions.*;
class SmokeTest {
 @Configuration @EnableAutoConfiguration static class App {}
 @Test void contextStarts() {
  var app = new SpringApplication(App.class);
  app.setWebApplicationType(WebApplicationType.NONE);
  try (var context = app.run()) { assertTrue(context.isActive()); }
 }
 @Test void frameworkAlignment() {
  assertEquals(System.getProperty("expectedFramework"), org.springframework.core.SpringVersion.getVersion());
 }
}'''
else:
    dependencies = '<dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>2.9.8</version></dependency>'
    recipe = '''  - org.openrewrite.maven.UpgradeDependencyVersion:
      groupId: com.fasterxml.jackson.core
      artifactId: jackson-databind
      newVersion: 2.13.5
'''
    test = '''package regression;
import org.junit.jupiter.api.Test;
import com.fasterxml.jackson.databind.ObjectMapper;
import static org.junit.jupiter.api.Assertions.*;
class SmokeTest {
 @Test void jsonRoundTrip() throws Exception {
  var mapper = new ObjectMapper();
  var node = mapper.readTree("{\\"name\\":\\"mantis\\",\\"items\\":[1,2,3]}");
  assertEquals(node, mapper.readTree(mapper.writeValueAsString(node)));
  assertEquals(3, node.get("items").size());
 }
}'''
write('pom.xml', f'''<project xmlns="http://maven.apache.org/POM/4.0.0">
<modelVersion>4.0.0</modelVersion>{parent}
<groupId>regression</groupId><artifactId>{name}</artifactId><version>1.0</version>
<properties><maven.compiler.release>21</maven.compiler.release><project.build.sourceEncoding>UTF-8</project.build.sourceEncoding></properties>
<dependencies>{dependencies}<dependency><groupId>org.junit.jupiter</groupId><artifactId>junit-jupiter</artifactId><version>5.11.0</version><scope>test</scope></dependency></dependencies>
<build><plugins><plugin><groupId>org.apache.maven.plugins</groupId><artifactId>maven-compiler-plugin</artifactId><version>3.13.0</version></plugin><plugin><groupId>org.apache.maven.plugins</groupId><artifactId>maven-surefire-plugin</artifactId><version>3.5.2</version></plugin></plugins></build>
</project>''')
write('src/test/java/regression/SmokeTest.java', test)
write('rewrite.yml', '# Existing repository-owned config must remain intact.\n')
original_config = (work / 'rewrite.yml').read_bytes()
write('mantis-test-recipe.yml', 'type: specs.openrewrite.org/v1beta/recipe\nname: regression.Fix\ndisplayName: Historical vulnerability fix\ndescription: Isolated regression fixture.\nrecipeList:\n' + recipe)
before_pom = (work / 'pom.xml').read_text()
baseline = scan(resolved('before-tree', before_version), 'before', True)
mvn('before-tests', 'verify', f'-DexpectedFramework={before_version}')
rewrite_args = ('org.openrewrite.maven:rewrite-maven-plugin:6.46.1:run',
                '-Drewrite.configLocation=mantis-test-recipe.yml', '-Drewrite.activeRecipes=regression.Fix')
mvn('rewrite', *rewrite_args)
after_pom = (work / 'pom.xml').read_text()
if before_pom == after_pom:
    raise AssertionError('Expected remediation made no changes')
if name == 'boot-managed':
    root = ET.fromstring(after_pom)
    assert root.find('m:parent/m:version', ns).text == '3.3.4'
    assert root.find('m:properties/m:spring-framework.version', ns) is None
    assert root.find('m:dependencyManagement', ns) is None
mvn('after-tests', 'clean', 'verify', f'-DexpectedFramework={after_version}')
fixed = scan(resolved('after-tree', after_version), 'after', False)
mvn('idempotence', *rewrite_args)
assert (work / 'pom.xml').read_text() == after_pom, 'Second rewrite changed POM'
assert (work / 'rewrite.yml').read_bytes() == original_config, 'Repository configuration changed'
reports = list((work / 'target/surefire-reports').glob('TEST-*.xml'))
assert reports, 'No tests executed'
count = 0
for report in reports:
    result = ET.parse(report).getroot()
    assert int(result.get('failures', '0')) == int(result.get('errors', '0')) == int(result.get('skipped', '0')) == 0
    count += int(result.get('tests', '0'))
assert count > 0
(out / f'{name}-remediation.patch').write_text(''.join(difflib.unified_diff(before_pom.splitlines(True), after_pom.splitlines(True), fromfile='before/pom.xml', tofile='after/pom.xml')))
(out / f'{name}-result.json').write_text(json.dumps({'scenario': name, 'target_cve': cve, 'before': baseline, 'after': fixed, 'tests': count, 'idempotent': True, 'scope': 'recipe regression, not Mantis service E2E'}, indent=2))
print(f'PASS: {name}; {count} tests; targeted advisory removed; rewrite idempotent')
