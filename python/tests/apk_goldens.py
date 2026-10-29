"""Expected values for test_apk_native.py, produced once by androguard 4.1.3
(scripts: apkbuild.py inputs; regenerate only if the inputs change).
Do not edit by hand."""

GOLDEN = {'axml_layout': (True,
                 True,
                 b'<androidx.constraintlayout.widget.ConstraintLayout xmlns:app="http://schemas.android.com/apk/res-aut'
                 b'o" xmlns:android="http://schemas.android.com/apk/res/android" xmlns:tools="http://schemas.android.co'
                 b'm/tools" android:layout_width="-1" android:layout_height="48.000000dip" android:android_UNKNOWN_SYST'
                 b'EM_ATTRIBUTE_0101ffff="3" app:layout_constraintTop_toTopOf="@00000000" tools:context=".MainActivity"'
                 b'>\n  <!--a comment-->\n  <TextView android:text="Hello &lt;world&gt; &amp; &quot;friends&quot;" an'
                 b'droid:hint="packed" _1bad_name_="v_al">some text</TextView>\n</androidx.constraintlayout.widget.C'
                 b'onstraintLayout>\n',
                 b'<androidx.constraintlayout.widget.ConstraintLayout xmlns:app="http://schemas.android.com/apk/res-aut'
                 b'o" xmlns:android="http://schemas.android.com/apk/res/android" xmlns:tools="http://schemas.android.co'
                 b'm/tools" android:layout_width="-1" android:layout_height="48.000000dip" android:android_UNKNOWN_SYST'
                 b'EM_ATTRIBUTE_0101ffff="3" app:layout_constraintTop_toTopOf="@00000000" tools:context=".MainActivity"'
                 b'><!--a comment--><TextView android:text="Hello &lt;world&gt; &amp; &quot;friends&quot;" android:hint'
                 b'="packed" _1bad_name_="v_al">some text</TextView></androidx.constraintlayout.widget.ConstraintLayout'
                 b'>'),
 'axml_manifest': (True,
                   False,
                   b'<manifest xmlns:android="http://schemas.android.com/apk/res/android" android:versionCode="42" an'
                   b'droid:versionName="4.2.0" package="com.example.app" platformBuildVersionCode="33">\n  <uses-sdk a'
                   b'ndroid:minSdkVersion="21" android:targetSdkVersion="33"/>\n  <uses-permission android:name="andro'
                   b'id.permission.INTERNET"/>\n  <uses-permission android:name="android.permission.CAMERA"/>\n  <uses-'
                   b'permission android:name="LOCAL_PERM"/>\n  <uses-permission android:name="android.permission.INTER'
                   b'NET"/>\n  <uses-permission android:name="android.permission.READ_CONTACTS" android:maxSdkVersion='
                   b'"22"/>\n  <permission android:name="com.example.app.PERM" android:label="@string/xapp_name" andro'
                   b'id:protectionLevel="0x00000002"/>\n  <application android:label="@7F0F0001" android:icon="@7F0800'
                   b'01" android:debuggable="true" android:allowBackup="false" android:theme="@android:01030237" andr'
                   b'oid:name=".App">\n    <activity android:name=".MainActivity" android:exported="true" android:them'
                   b'e="?7F040123">\n      <intent-filter>\n        <action android:name="android.intent.action.MAIN"/>'
                   b'\n        <category android:name="android.intent.category.LAUNCHER"/>\n      </intent-filter>\n'
                   b'    </activity>\n    <activity android:name="SettingsActivity"/>\n    <activity-alias android:name'
                   b'=".Alias" android:targetActivity=".MainActivity"/>\n    <service android:name="com.example.app.Sy'
                   b'ncService" android:exported="false"/>\n    <receiver android:name=".BootReceiver"/>\n    <provider'
                   b' android:name="androidx.core.content.FileProvider" android:authorities="com.example.app.files"/>'
                   b'\n    <meta-data android:name="k.f" android:value="1.500000"/>\n    <meta-data android:name="k.d" '
                   b'android:value="16.000000dip"/>\n    <meta-data android:name="k.fr" android:value="3276800.000000%'
                   b'"/>\n    <meta-data android:name="k.c" android:value="#FF00FF00"/>\n    <meta-data android:name="k'
                   b'.h" android:value="0xDEADBEEF"/>\n    <meta-data android:name="k.n" android:value="-5"/>\n    <met'
                   b'a-data android:name="k.unk" android:value="&lt;0x4D2, type 0x07&gt;"/>\n  </application>\n</manife'
                   b'st>\n',
                   b'<manifest xmlns:android="http://schemas.android.com/apk/res/android" android:versionCode="42" an'
                   b'droid:versionName="4.2.0" package="com.example.app" platformBuildVersionCode="33"><uses-sdk andr'
                   b'oid:minSdkVersion="21" android:targetSdkVersion="33"/><uses-permission android:name="android.per'
                   b'mission.INTERNET"/><uses-permission android:name="android.permission.CAMERA"/><uses-permission a'
                   b'ndroid:name="LOCAL_PERM"/><uses-permission android:name="android.permission.INTERNET"/><uses-per'
                   b'mission android:name="android.permission.READ_CONTACTS" android:maxSdkVersion="22"/><permission '
                   b'android:name="com.example.app.PERM" android:label="@string/xapp_name" android:protectionLevel="0'
                   b'x00000002"/><application android:label="@7F0F0001" android:icon="@7F080001" android:debuggable="'
                   b'true" android:allowBackup="false" android:theme="@android:01030237" android:name=".App"><activit'
                   b'y android:name=".MainActivity" android:exported="true" android:theme="?7F040123"><intent-filter>'
                   b'<action android:name="android.intent.action.MAIN"/><category android:name="android.intent.catego'
                   b'ry.LAUNCHER"/></intent-filter></activity><activity android:name="SettingsActivity"/><activity-al'
                   b'ias android:name=".Alias" android:targetActivity=".MainActivity"/><service android:name="com.exa'
                   b'mple.app.SyncService" android:exported="false"/><receiver android:name=".BootReceiver"/><provide'
                   b'r android:name="androidx.core.content.FileProvider" android:authorities="com.example.app.files"/'
                   b'><meta-data android:name="k.f" android:value="1.500000"/><meta-data android:name="k.d" android:v'
                   b'alue="16.000000dip"/><meta-data android:name="k.fr" android:value="3276800.000000%"/><meta-data '
                   b'android:name="k.c" android:value="#FF00FF00"/><meta-data android:name="k.h" android:value="0xDEA'
                   b'DBEEF"/><meta-data android:name="k.n" android:value="-5"/><meta-data android:name="k.unk" androi'
                   b'd:value="&lt;0x4D2, type 0x07&gt;"/></application></manifest>'),
 'axml_packed': (True,
                 False,
                 b'<network-security-config xmlns:android="http://schemas.android.com/apk/res/android">\n  <domain-c'
                 b'onfig cleartextTrafficPermitted="true">\n    <domain includeSubdomains="true">example.com'
                 b' \xc3\xa9\xe4\xb8\xad</domain>\n  </domain-config>\n</network-security-config>\n',
                 b'<network-security-config xmlns:android="http://schemas.android.com/apk/res/android"><domain-config c'
                 b'leartextTrafficPermitted="true"><domain includeSubdomains="true">example.com \xc3\xa9\xe4\xb8\xad</'
                 b'domain></domain-config></network-security-config>'),
 'filename': 'raw_apk_sha256:af7ac3181432dde9d3c1f0afae8d9264247747342e1b0384a99b65f6ec20ab10',
 'get_activities': ['com.example.app.MainActivity', 'com.example.app.SettingsActivity'],
 'get_activity_aliases': [{'name': 'com.example.app.Alias', 'targetActivity': 'com.example.app.MainActivity'}],
 'get_androidversion_code': '42',
 'get_androidversion_name': '4.2.0',
 'get_certificates_der_v2': [b'0\x06CERT-A', b'0\x06CERT-B'],
 'get_certificates_der_v3': [b'0\x06CERT-C'],
 'get_declared_permissions': ['com.example.app.PERM'],
 'get_declared_permissions_details': {'com.example.app.PERM': {'description': 'None',
                                                               'label': 'Example',
                                                               'permissionGroup': 'None',
                                                               'protectionLevel': '0x00000002'}},
 'get_dex_names': ['classes.dex'],
 'get_effective_target_sdk_version': 33,
 'get_files': ['AndroidManifest.xml',
               'classes.dex',
               'res/layout/main.xml',
               'res/xml/network_security_config.xml',
               'resources.arsc',
               'META-INF/CERT.SF',
               'META-INF/CERT.RSA',
               'META-INF/ORPHAN.EC',
               'assets/a.txt'],
 'get_libraries': [],
 'get_main_activity': 'com.example.app.MainActivity',
 'get_max_sdk_version': None,
 'get_min_sdk_version': '21',
 'get_package': 'com.example.app',
 'get_permissions': ['android.permission.CAMERA',
                     'android.permission.INTERNET',
                     'android.permission.READ_CONTACTS',
                     'com.example.app.LOCAL_PERM'],
 'get_providers': ['androidx.core.content.FileProvider'],
 'get_receivers': ['com.example.app.BootReceiver'],
 'get_services': ['com.example.app.SyncService'],
 'get_signature_names': ['META-INF/CERT.RSA'],
 'get_string_resources': b'<?xml version="1.0" encoding="utf-8"?>\n<resources>\n<string name="app_name">Example</stri'
                         b'ng>\n<string name="html"><![CDATA[<b>bold</b> & co]]></string>\n</resources>\n',
 'get_target_sdk_version': '33',
 'is_multidex': False,
 'is_signed': True,
 'is_signed_v1': True,
 'is_signed_v2': True,
 'is_signed_v3': True,
 'manifest_tostring': b'<manifest xmlns:android="http://schemas.android.com/apk/res/android" android:versionCode="42'
                      b'" android:versionName="4.2.0" package="com.example.app" platformBuildVersionCode="33"><uses-'
                      b'sdk android:minSdkVersion="21" android:targetSdkVersion="33"/><uses-permission android:name='
                      b'"android.permission.INTERNET"/><uses-permission android:name="android.permission.CAMERA"/><u'
                      b'ses-permission android:name="LOCAL_PERM"/><uses-permission android:name="android.permission.'
                      b'INTERNET"/><uses-permission android:name="android.permission.READ_CONTACTS" android:maxSdkVe'
                      b'rsion="22"/><permission android:name="com.example.app.PERM" android:label="@string/xapp_name'
                      b'" android:protectionLevel="0x00000002"/><application android:label="@7F0F0001" android:icon='
                      b'"@7F080001" android:debuggable="true" android:allowBackup="false" android:theme="@android:01'
                      b'030237" android:name=".App"><activity android:name=".MainActivity" android:exported="true" a'
                      b'ndroid:theme="?7F040123"><intent-filter><action android:name="android.intent.action.MAIN"/><'
                      b'category android:name="android.intent.category.LAUNCHER"/></intent-filter></activity><activi'
                      b'ty android:name="SettingsActivity"/><activity-alias android:name=".Alias" android:targetActi'
                      b'vity=".MainActivity"/><service android:name="com.example.app.SyncService" android:exported="'
                      b'false"/><receiver android:name=".BootReceiver"/><provider android:name="androidx.core.conten'
                      b't.FileProvider" android:authorities="com.example.app.files"/><meta-data android:name="k.f" a'
                      b'ndroid:value="1.500000"/><meta-data android:name="k.d" android:value="16.000000dip"/><meta-d'
                      b'ata android:name="k.fr" android:value="3276800.000000%"/><meta-data android:name="k.c" andro'
                      b'id:value="#FF00FF00"/><meta-data android:name="k.h" android:value="0xDEADBEEF"/><meta-data a'
                      b'ndroid:name="k.n" android:value="-5"/><meta-data android:name="k.unk" android:value="&lt;0x4'
                      b'D2, type 0x07&gt;"/></application></manifest>',
 'res_string_value': '<b>bold</b> & co',
 'uses_permissions': ["['LOCAL_PERM', None]",
                      "['android.permission.CAMERA', None]",
                      "['android.permission.INTERNET', None]",
                      "['android.permission.INTERNET', None]",
                      "['android.permission.READ_CONTACTS', 22]"]}
