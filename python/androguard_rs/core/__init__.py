"""``androguard.core``: androguard 4.1.3's module paths over this package.

``androguard_rs.core.apk``, ``.dex``, ``.axml``, ``.api_specific_resources``
and ``.analysis.analysis`` are the modules ``androguard_rs.apk``, ``.dex``,
``.axml``, ``.api_specific_resources`` and ``.analysis`` themselves (the same
module objects, so the same classes), registered under androguard's names when
first imported. ``androguard_rs.core.androconf`` provides
``load_api_specific_resource_module``. Code written against androguard
switches by renaming ``androguard`` to ``androguard_rs`` in its imports.
"""
