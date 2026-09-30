from xml.sax.saxutils import escape as xml_escape
import os
import json
import zipfile
import shutil

def pack_package(pkg_dir, package_id, display_name, description):
    # Read version and details from package.json
    pkg_json_path = os.path.join(pkg_dir, 'package.json')
    version = "5.4.26"
    publisher = "bartholomew"
    keywords = "ai,security,agent,mcp,trust,guardrails,cursor,copilot"
    categories = "Machine Learning,Security,Other"
    
    if os.path.exists(pkg_json_path):
        with open(pkg_json_path, 'r', encoding='utf-8') as f:
            vinfo = json.load(f)
            version = vinfo.get('version', version)
            publisher = vinfo.get('publisher', publisher)
            if 'keywords' in vinfo:
                keywords = ','.join(vinfo['keywords'])
            if 'categories' in vinfo:
                categories = ','.join(vinfo['categories'])

    out_vsix_name = f"{package_id}-{version}.vsix"
    out_vsix = os.path.join(pkg_dir, out_vsix_name)
    
    content_types_xml = """<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension=".json" ContentType="application/json"/>
  <Default Extension=".vsixmanifest" ContentType="text/xml"/>
  <Default Extension=".js" ContentType="application/javascript"/>
  <Default Extension=".png" ContentType="image/png"/>
  <Default Extension=".svg" ContentType="image/svg+xml"/>
  <Default Extension=".md" ContentType="text/markdown"/>
  <Default Extension=".ts" ContentType="video/mp2t"/>
</Types>"""

    vsixmanifest_xml = f"""<?xml version="1.0" encoding="utf-8"?>
<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011" xmlns:d="http://schemas.microsoft.com/developer/vsx-schema-design/2011">
  <Metadata>
    <Identity Language="en-US" Id="{package_id}" Version="{version}" Publisher="{publisher}" />
    <DisplayName>{xml_escape(display_name)}</DisplayName>
    <Description xml:space="preserve">{xml_escape(description)}</Description>
    <Tags>{keywords}</Tags>
    <Categories>{categories}</Categories>
    <GalleryFlags>Public</GalleryFlags>
    
    <Properties>
      <Property Id="Microsoft.VisualStudio.Code.Engine" Value="^1.80.0" />
      <Property Id="Microsoft.VisualStudio.Code.ExtensionDependencies" Value="" />
      <Property Id="Microsoft.VisualStudio.Code.ExtensionPack" Value="" />
      <Property Id="Microsoft.VisualStudio.Code.ExtensionKind" Value="workspace" />
      <Property Id="Microsoft.VisualStudio.Code.LocalizedLanguages" Value="" />
      <Property Id="Microsoft.VisualStudio.Code.EnabledApiProposals" Value="" />
      <Property Id="Microsoft.VisualStudio.Code.ExecutesCode" Value="true" />
      <Property Id="Microsoft.VisualStudio.Services.Links.Source" Value="https://github.com/bartholomew-ai/bartholomew.git" />
      <Property Id="Microsoft.VisualStudio.Services.Links.Getstarted" Value="https://github.com/bartholomew-ai/bartholomew.git" />
      <Property Id="Microsoft.VisualStudio.Services.Links.GitHub" Value="https://github.com/bartholomew-ai/bartholomew.git" />
      <Property Id="Microsoft.VisualStudio.Services.Links.Support" Value="https://github.com/bartholomew-ai/bartholomew/issues" />
      <Property Id="Microsoft.VisualStudio.Services.Links.Learn" Value="https://github.com/bartholomew-ai/bartholomew#readme" />
      <Property Id="Microsoft.VisualStudio.Services.GitHubFlavoredMarkdown" Value="true" />
      <Property Id="Microsoft.VisualStudio.Services.Content.Pricing" Value="Free"/>
    </Properties>
    <License>extension/LICENSE.md</License>
    <Icon>extension/icon.png</Icon>
  </Metadata>
  <Installation>
    <InstallationTarget Id="Microsoft.VisualStudio.Code"/>
  </Installation>
  <Dependencies/>
  <Assets>
    <Asset Type="Microsoft.VisualStudio.Code.Manifest" Path="extension/package.json" Addressable="true" />
    <Asset Type="Microsoft.VisualStudio.Services.Content.Details" Path="extension/README.md" Addressable="true" />
    <Asset Type="Microsoft.VisualStudio.Services.Content.License" Path="extension/LICENSE.md" Addressable="true" />
    <Asset Type="Microsoft.VisualStudio.Services.Icons.Default" Path="extension/icon.png" Addressable="true" />
  </Assets>
</PackageManifest>"""

    with zipfile.ZipFile(out_vsix, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('[Content_Types].xml', content_types_xml)
        z.writestr('extension.vsixmanifest', vsixmanifest_xml)
        for root, dirs, files in os.walk(pkg_dir):
            if 'node_modules' in root or '.git' in root or '.vsix' in root:
                continue
            for f in files:
                if f.endswith('.vsix'):
                    continue
                fp = os.path.join(root, f)
                rel = os.path.relpath(fp, pkg_dir)
                z.write(fp, 'extension/' + rel.replace('\\', '/'))

    size = os.path.getsize(out_vsix)
    print(f"[+] Successfully packaged {out_vsix} ({size:,} bytes) with GalleryFlags=Public")
    
    # Also write 1.0.0 copy for any legacy CI/CD references
    legacy_vsix = os.path.join(pkg_dir, f"{package_id}-1.0.0.vsix")
    shutil.copyfile(out_vsix, legacy_vsix)
    return out_vsix

if __name__ == '__main__':
    root = os.path.abspath('.')
    pack_package(
        os.path.join(root, 'packages/bartholomew-keystone'),
        'bartholomew-keystone',
        'Bartholomew Keystone - AI Agent Capabilities & Passkeys (Cursor, Claude)',
        'Cryptographically signed clearance tokens granting autonomous AI agents fine-grained access across files, commands, and domains in Cursor, Claude Desktop, and VS Code.'
    )
    pack_package(
        os.path.join(root, 'packages/vscode-extension'),
        'bartholomew-guard-vscode',
        'Bartholomew AI Agent Guard - Security & Guardrails (Cursor, Claude, Copilot)',
        'Zero-trust firewall & security guardrails for AI agents. Prevents dangerous commands, secret exfiltration, and destructive file deletion in Cursor, Claude Desktop, and VS Code.'
    )
