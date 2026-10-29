"""``androguard.core.axml.ARSCResTableConfig`` from androguard 4.1.3, verbatim
(Apache-2.0; its debug logging dropped), with the configuration constants
it uses, so ``ARSCParser.get_resolved_res_configs()`` can return the same
objects: every attribute, ``repr()``, ``==``/``hash()``, ``get_qualifier()``
and the other methods behave as androguard's.

``from_bytes(start, raw)`` builds one from the bytes androguard's
constructor read at offset ``start`` of the table (``start`` is kept, as
androguard keeps ``buff.tell()``).

Generated from androguard/core/axml/__init__.py (4.1.3): the constants at
lines 1434-1621 and the class at lines 2996-3526.
"""

from struct import unpack
from typing import BinaryIO, Union


class _NoLog:
    @staticmethod
    def debug(*args, **kwargs):
        pass


logger = _NoLog()

ACONFIGURATION_ORIENTATION_ANY = 0x0000
ACONFIGURATION_ORIENTATION_PORT = 0x0001
ACONFIGURATION_ORIENTATION_LAND = 0x0002
ACONFIGURATION_ORIENTATION_SQUARE = 0x0003
ACONFIGURATION_TOUCHSCREEN_ANY = 0x0000
ACONFIGURATION_TOUCHSCREEN_NOTOUCH = 0x0001
ACONFIGURATION_TOUCHSCREEN_STYLUS = 0x0002
ACONFIGURATION_TOUCHSCREEN_FINGER = 0x0003
ACONFIGURATION_DENSITY_DEFAULT = 0
ACONFIGURATION_DENSITY_LOW = 120
ACONFIGURATION_DENSITY_MEDIUM = 160
ACONFIGURATION_DENSITY_TV = 213
ACONFIGURATION_DENSITY_HIGH = 240
ACONFIGURATION_DENSITY_XHIGH = 320
ACONFIGURATION_DENSITY_XXHIGH = 480
ACONFIGURATION_DENSITY_XXXHIGH = 640
ACONFIGURATION_DENSITY_ANY = 0xFFFE
ACONFIGURATION_DENSITY_NONE = 0xFFFF
ACONFIGURATION_KEYBOARD_ANY = 0x0000
ACONFIGURATION_KEYBOARD_NOKEYS = 0x0001
ACONFIGURATION_KEYBOARD_QWERTY = 0x0002
ACONFIGURATION_KEYBOARD_12KEY = 0x0003
ACONFIGURATION_NAVIGATION_ANY = 0x0000
ACONFIGURATION_NAVIGATION_NONAV = 0x0001
ACONFIGURATION_NAVIGATION_DPAD = 0x0002
ACONFIGURATION_NAVIGATION_TRACKBALL = 0x0003
ACONFIGURATION_NAVIGATION_WHEEL = 0x0004
ACONFIGURATION_KEYSHIDDEN_ANY = 0x0000
ACONFIGURATION_KEYSHIDDEN_NO = 0x0001
ACONFIGURATION_KEYSHIDDEN_YES = 0x0002
ACONFIGURATION_KEYSHIDDEN_SOFT = 0x0003
ACONFIGURATION_NAVHIDDEN_ANY = 0x0000
ACONFIGURATION_NAVHIDDEN_NO = 0x0001
ACONFIGURATION_NAVHIDDEN_YES = 0x0002
ACONFIGURATION_SCREENSIZE_ANY = 0x00
ACONFIGURATION_SCREENSIZE_SMALL = 0x01
ACONFIGURATION_SCREENSIZE_NORMAL = 0x02
ACONFIGURATION_SCREENSIZE_LARGE = 0x03
ACONFIGURATION_SCREENSIZE_XLARGE = 0x04
ACONFIGURATION_SCREENLONG_ANY = 0x00
ACONFIGURATION_SCREENLONG_NO = 0x1
ACONFIGURATION_SCREENLONG_YES = 0x2
ACONFIGURATION_SCREENROUND_ANY = 0x00
ACONFIGURATION_SCREENROUND_NO = 0x1
ACONFIGURATION_SCREENROUND_YES = 0x2
ACONFIGURATION_WIDE_COLOR_GAMUT_ANY = 0x00
ACONFIGURATION_WIDE_COLOR_GAMUT_NO = 0x1
ACONFIGURATION_WIDE_COLOR_GAMUT_YES = 0x2
ACONFIGURATION_HDR_ANY = 0x00
ACONFIGURATION_HDR_NO = 0x1
ACONFIGURATION_HDR_YES = 0x2
ACONFIGURATION_UI_MODE_TYPE_ANY = 0x00
ACONFIGURATION_UI_MODE_TYPE_NORMAL = 0x01
ACONFIGURATION_UI_MODE_TYPE_DESK = 0x02
ACONFIGURATION_UI_MODE_TYPE_CAR = 0x03
ACONFIGURATION_UI_MODE_TYPE_TELEVISION = 0x04
ACONFIGURATION_UI_MODE_TYPE_APPLIANCE = 0x05
ACONFIGURATION_UI_MODE_TYPE_WATCH = 0x06
ACONFIGURATION_UI_MODE_TYPE_VR_HEADSET = 0x07
ACONFIGURATION_UI_MODE_NIGHT_ANY = 0x00
ACONFIGURATION_UI_MODE_NIGHT_NO = 0x1
ACONFIGURATION_UI_MODE_NIGHT_YES = 0x2
ACONFIGURATION_SCREEN_WIDTH_DP_ANY = 0x0000
ACONFIGURATION_SCREEN_HEIGHT_DP_ANY = 0x0000
ACONFIGURATION_SMALLEST_SCREEN_WIDTH_DP_ANY = 0x0000
ACONFIGURATION_LAYOUTDIR_ANY = 0x00
ACONFIGURATION_LAYOUTDIR_LTR = 0x01
ACONFIGURATION_LAYOUTDIR_RTL = 0x02
ACONFIGURATION_MCC = 0x0001
ACONFIGURATION_MNC = 0x0002
ACONFIGURATION_LOCALE = 0x0004
ACONFIGURATION_TOUCHSCREEN = 0x0008
ACONFIGURATION_KEYBOARD = 0x0010
ACONFIGURATION_KEYBOARD_HIDDEN = 0x0020
ACONFIGURATION_NAVIGATION = 0x0040
ACONFIGURATION_ORIENTATION = 0x0080
ACONFIGURATION_DENSITY = 0x0100
ACONFIGURATION_SCREEN_SIZE = 0x0200
ACONFIGURATION_VERSION = 0x0400
ACONFIGURATION_SCREEN_LAYOUT = 0x0800
ACONFIGURATION_UI_MODE = 0x1000
ACONFIGURATION_SMALLEST_SCREEN_SIZE = 0x2000
ACONFIGURATION_LAYOUTDIR = 0x4000
ACONFIGURATION_SCREEN_ROUND = 0x8000
ACONFIGURATION_COLOR_MODE = 0x10000
ACONFIGURATION_MNC_ZERO = 0xFFFF

# See http://aospxref.com/android-13.0.0_r3/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#946

ORIENTATION_ANY = ACONFIGURATION_ORIENTATION_ANY
ORIENTATION_PORT = ACONFIGURATION_ORIENTATION_PORT
ORIENTATION_LAND = ACONFIGURATION_ORIENTATION_LAND
ORIENTATION_SQUARE = ACONFIGURATION_ORIENTATION_SQUARE

TOUCHSCREEN_ANY = ACONFIGURATION_TOUCHSCREEN_ANY
TOUCHSCREEN_NOTOUCH = ACONFIGURATION_TOUCHSCREEN_NOTOUCH
TOUCHSCREEN_STYLUS = ACONFIGURATION_TOUCHSCREEN_STYLUS
TOUCHSCREEN_FINGER = ACONFIGURATION_TOUCHSCREEN_FINGER

DENSITY_DEFAULT = ACONFIGURATION_DENSITY_DEFAULT
DENSITY_LOW = ACONFIGURATION_DENSITY_LOW
DENSITY_MEDIUM = ACONFIGURATION_DENSITY_MEDIUM
DENSITY_TV = ACONFIGURATION_DENSITY_TV
DENSITY_HIGH = ACONFIGURATION_DENSITY_HIGH
DENSITY_XHIGH = ACONFIGURATION_DENSITY_XHIGH
DENSITY_XXHIGH = ACONFIGURATION_DENSITY_XXHIGH
DENSITY_XXXHIGH = ACONFIGURATION_DENSITY_XXXHIGH
DENSITY_ANY = ACONFIGURATION_DENSITY_ANY
DENSITY_NONE = ACONFIGURATION_DENSITY_NONE

KEYBOARD_ANY = ACONFIGURATION_KEYBOARD_ANY
KEYBOARD_NOKEYS = ACONFIGURATION_KEYBOARD_NOKEYS
KEYBOARD_QWERTY = ACONFIGURATION_KEYBOARD_QWERTY
KEYBOARD_12KEY = ACONFIGURATION_KEYBOARD_12KEY

NAVIGATION_ANY = ACONFIGURATION_NAVIGATION_ANY
NAVIGATION_NONAV = ACONFIGURATION_NAVIGATION_NONAV
NAVIGATION_DPAD = ACONFIGURATION_NAVIGATION_DPAD
NAVIGATION_TRACKBALL = ACONFIGURATION_NAVIGATION_TRACKBALL
NAVIGATION_WHEEL = ACONFIGURATION_NAVIGATION_WHEEL

MASK_KEYSHIDDEN = 0x0003
KEYSHIDDEN_ANY = ACONFIGURATION_KEYSHIDDEN_ANY
KEYSHIDDEN_NO = ACONFIGURATION_KEYSHIDDEN_NO
KEYSHIDDEN_YES = ACONFIGURATION_KEYSHIDDEN_YES
KEYSHIDDEN_SOFT = ACONFIGURATION_KEYSHIDDEN_SOFT

MASK_NAVHIDDEN = 0x000C
SHIFT_NAVHIDDEN = 2
NAVHIDDEN_ANY = ACONFIGURATION_NAVHIDDEN_ANY << SHIFT_NAVHIDDEN
NAVHIDDEN_NO = ACONFIGURATION_NAVHIDDEN_NO << SHIFT_NAVHIDDEN
NAVHIDDEN_YES = ACONFIGURATION_NAVHIDDEN_YES << SHIFT_NAVHIDDEN

SCREENWIDTH_ANY = 0
SCREENHEIGHT_ANY = 0
SDKVERSION_ANY = 0
MINORVERSION_ANY = 0

MASK_SCREENSIZE = 0x0F
SCREENSIZE_ANY = ACONFIGURATION_SCREENSIZE_ANY
SCREENSIZE_SMALL = ACONFIGURATION_SCREENSIZE_SMALL
SCREENSIZE_NORMAL = ACONFIGURATION_SCREENSIZE_NORMAL
SCREENSIZE_LARGE = ACONFIGURATION_SCREENSIZE_LARGE
SCREENSIZE_XLARGE = ACONFIGURATION_SCREENSIZE_XLARGE

MASK_SCREENLONG = 0x30
SHIFT_SCREENLONG = 4
SCREENLONG_ANY = ACONFIGURATION_SCREENLONG_ANY << SHIFT_SCREENLONG
SCREENLONG_NO = ACONFIGURATION_SCREENLONG_NO << SHIFT_SCREENLONG
SCREENLONG_YES = ACONFIGURATION_SCREENLONG_YES << SHIFT_SCREENLONG

MASK_LAYOUTDIR = 0xC0
SHIFT_LAYOUTDIR = 6
LAYOUTDIR_ANY = ACONFIGURATION_LAYOUTDIR_ANY << SHIFT_LAYOUTDIR
LAYOUTDIR_LTR = ACONFIGURATION_LAYOUTDIR_LTR << SHIFT_LAYOUTDIR
LAYOUTDIR_RTL = ACONFIGURATION_LAYOUTDIR_RTL << SHIFT_LAYOUTDIR

MASK_UI_MODE_TYPE = 0x0F
UI_MODE_TYPE_ANY = ACONFIGURATION_UI_MODE_TYPE_ANY
UI_MODE_TYPE_NORMAL = ACONFIGURATION_UI_MODE_TYPE_NORMAL
UI_MODE_TYPE_DESK = ACONFIGURATION_UI_MODE_TYPE_DESK
UI_MODE_TYPE_CAR = ACONFIGURATION_UI_MODE_TYPE_CAR
UI_MODE_TYPE_TELEVISION = ACONFIGURATION_UI_MODE_TYPE_TELEVISION
UI_MODE_TYPE_APPLIANCE = ACONFIGURATION_UI_MODE_TYPE_APPLIANCE
UI_MODE_TYPE_WATCH = ACONFIGURATION_UI_MODE_TYPE_WATCH
UI_MODE_TYPE_VR_HEADSET = ACONFIGURATION_UI_MODE_TYPE_VR_HEADSET

MASK_UI_MODE_NIGHT = 0x30
SHIFT_UI_MODE_NIGHT = 4
UI_MODE_NIGHT_ANY = ACONFIGURATION_UI_MODE_NIGHT_ANY << SHIFT_UI_MODE_NIGHT
UI_MODE_NIGHT_NO = ACONFIGURATION_UI_MODE_NIGHT_NO << SHIFT_UI_MODE_NIGHT
UI_MODE_NIGHT_YES = ACONFIGURATION_UI_MODE_NIGHT_YES << SHIFT_UI_MODE_NIGHT

MASK_SCREENROUND = 0x03
SCREENROUND_ANY = ACONFIGURATION_SCREENROUND_ANY
SCREENROUND_NO = ACONFIGURATION_SCREENROUND_NO
SCREENROUND_YES = ACONFIGURATION_SCREENROUND_YES

MASK_WIDE_COLOR_GAMUT = 0x03
WIDE_COLOR_GAMUT_ANY = ACONFIGURATION_WIDE_COLOR_GAMUT_ANY
WIDE_COLOR_GAMUT_NO = ACONFIGURATION_WIDE_COLOR_GAMUT_NO
WIDE_COLOR_GAMUT_YES = ACONFIGURATION_WIDE_COLOR_GAMUT_YES

MASK_HDR = 0x0C
SHIFT_HDR = 2
HDR_ANY = ACONFIGURATION_HDR_ANY << SHIFT_HDR
HDR_NO = ACONFIGURATION_HDR_NO << SHIFT_HDR
HDR_YES = ACONFIGURATION_HDR_YES << SHIFT_HDR


class ARSCResTableConfig:
    """
    ARSCResTableConfig contains the configuration for specific resource selection.
    This is used on the device to determine which resources should be loaded
    based on different properties of the device like locale or displaysize.

    See the definition of `ResTable_config` in
    http://androidxref.com/9.0.0_r3/xref/frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h#911
    """

    @classmethod
    def default_config(cls):
        if not hasattr(cls, 'DEFAULT'):
            cls.DEFAULT = ARSCResTableConfig(None)
        return cls.DEFAULT

    def __init__(self, buff: Union[BinaryIO, None] = None, **kwargs) -> None:
        if buff is not None:
            self.start = buff.tell()

            # uint32_t
            self.size = unpack('<I', buff.read(4))[0]

            # union: uint16_t mcc, uint16_t mnc
            # 0 means any
            self.imsi = unpack('<I', buff.read(4))[0]

            # uint32_t as chars \0\0 means any
            # either two 7bit ASCII representing the ISO-639-1 language code
            # or a single 16bit LE value representing ISO-639-2 3 letter code
            self.locale = unpack('<I', buff.read(4))[0]

            # struct of:
            # uint8_t orientation
            # uint8_t touchscreen
            # uint16_t density
            self.screenType = unpack('<I', buff.read(4))[0]

            if self.size >= 20:
                # struct of
                # uint8_t keyboard
                # uint8_t navigation
                # uint8_t inputFlags
                # uint8_t inputPad0
                self.input = unpack('<I', buff.read(4))[0]
            else:
                logger.debug(
                    "This file does not have input flags! size={}".format(
                        self.size
                    )
                )
                self.input = 0

            if self.size >= 24:
                # struct of
                # uint16_t screenWidth
                # uint16_t screenHeight
                self.screenSize = unpack('<I', buff.read(4))[0]
            else:
                logger.debug(
                    "This file does not have screenSize! size={}".format(
                        self.size
                    )
                )
                self.screenSize = 0

            if self.size >= 28:
                # struct of
                # uint16_t sdkVersion
                # uint16_t minorVersion  which should be always 0, as the meaning is not defined
                self.version = unpack('<I', buff.read(4))[0]
            else:
                logger.debug(
                    "This file does not have version! size={}".format(
                        self.size
                    )
                )
                self.version = 0

            # The next three fields seems to be optional
            if self.size >= 32:
                # struct of
                # uint8_t screenLayout
                # uint8_t uiMode
                # uint16_t smallestScreenWidthDp
                (self.screenConfig,) = unpack('<I', buff.read(4))
            else:
                logger.debug(
                    "This file does not have a screenConfig! size={}".format(
                        self.size
                    )
                )
                self.screenConfig = 0

            if self.size >= 36:
                # struct of
                # uint16_t screenWidthDp
                # uint16_t screenHeightDp
                (self.screenSizeDp,) = unpack('<I', buff.read(4))
            else:
                logger.debug(
                    "This file does not have a screenSizeDp! size={}".format(
                        self.size
                    )
                )
                self.screenSizeDp = 0

            if self.size >= 40:
                self.localeScript = buff.read(4)

            if self.size >= 44:
                self.localeVariant = buff.read(8)

            if self.size >= 52:
                # struct of
                # uint8_t screenLayout2
                # uint8_t colorMode
                # uint16_t screenConfigPad2
                (self.screenConfig2,) = unpack("<I", buff.read(4))
            else:
                logger.debug(
                    "This file does not have a screenConfig2! size={}".format(
                        self.size
                    )
                )
                self.screenConfig2 = 0

            self.exceedingSize = self.size - (buff.tell() - self.start)
            if self.exceedingSize > 0:
                logger.debug("Skipping padding bytes!")
                self.padding = buff.read(self.exceedingSize)

        else:
            self.start = 0
            self.size = 0
            self.imsi = ((kwargs.pop('mcc', 0) & 0xFFFF) << 0) + (
                (kwargs.pop('mnc', 0) & 0xFFFF) << 16
            )

            temp_locale = kwargs.pop('locale', 0)
            if isinstance(temp_locale, str):
                self.set_language_and_region(temp_locale)
            else:
                self.locale = temp_locale

            for char_ix, char in kwargs.pop('locale', "")[0:4]:
                self.locale += ord(char) << (char_ix * 8)

            self.screenType = (
                ((kwargs.pop('orientation', 0) & 0xFF) << 0)
                + ((kwargs.pop('touchscreen', 0) & 0xFF) << 8)
                + ((kwargs.pop('density', 0) & 0xFFFF) << 16)
            )

            self.input = (
                ((kwargs.pop('keyboard', 0) & 0xFF) << 0)
                + ((kwargs.pop('navigation', 0) & 0xFF) << 8)
                + ((kwargs.pop('inputFlags', 0) & 0xFF) << 16)
                + ((kwargs.pop('inputPad0', 0) & 0xFF) << 24)
            )

            self.screenSize = (
                (kwargs.pop('screenWidth', 0) & 0xFFFF) << 0
            ) + ((kwargs.pop('screenHeight', 0) & 0xFFFF) << 16)

            self.version = ((kwargs.pop('sdkVersion', 0) & 0xFFFF) << 0) + (
                (kwargs.pop('minorVersion', 0) & 0xFFFF) << 16
            )

            self.screenConfig = (
                ((kwargs.pop('screenLayout', 0) & 0xFF) << 0)
                + ((kwargs.pop('uiMode', 0) & 0xFF) << 8)
                + ((kwargs.pop('smallestScreenWidthDp', 0) & 0xFFFF) << 16)
            )

            self.screenSizeDp = (
                (kwargs.pop('screenWidthDp', 0) & 0xFFFF) << 0
            ) + ((kwargs.pop('screenHeightDp', 0) & 0xFFFF) << 16)

            # TODO add this some day...
            self.screenConfig2 = 0

            self.exceedingSize = 0

    def _unpack_language_or_region(self, char_in, char_base):
        char_out = ""
        if char_in[0] & 0x80:
            first = char_in[1] & 0x1F
            second = ((char_in[1] & 0xE0) >> 5) + ((char_in[0] & 0x03) << 3)
            third = (char_in[0] & 0x7C) >> 2
            char_out += chr(first + char_base)
            char_out += chr(second + char_base)
            char_out += chr(third + char_base)
        else:
            if char_in[0]:
                char_out += chr(char_in[0])
            if char_in[1]:
                char_out += chr(char_in[1])
        return char_out

    def _pack_language_or_region(self, char_in: str) -> list[int]:
        char_out = [0x00, 0x00]
        if len(char_in) != 2:
            return char_out
        char_out[0] = ord(char_in[0])
        char_out[1] = ord(char_in[1])
        return char_out

    def set_language_and_region(self, language_region):
        try:
            language, region = language_region.split("-r")
        except ValueError:
            language, region = language_region, None
        language_bytes = self._pack_language_or_region(language)
        if region:
            region_bytes = self._pack_language_or_region(region)
        else:
            region_bytes = [0x00, 0x00]
        self.locale = (
            language_bytes[0]
            | (language_bytes[1] << 8)
            | (region_bytes[0] << 16)
            | (region_bytes[1] << 24)
        )

    def get_language_and_region(self) -> str:
        """
        Returns the combined language+region string or \x00\x00 for the default locale
        :returns: the combined language and region string
        """
        if self.locale != 0:
            _language = self._unpack_language_or_region(
                [
                    self.locale & 0xFF,
                    (self.locale & 0xFF00) >> 8,
                ],
                ord('a'),
            )
            _region = self._unpack_language_or_region(
                [
                    (self.locale & 0xFF0000) >> 16,
                    (self.locale & 0xFF000000) >> 24,
                ],
                ord('0'),
            )
            return (_language + "-r" + _region) if _region else _language
        return "\x00\x00"

    def get_config_name_friendly(self) -> str:
        """
        Here for legacy reasons.

        use [get_qualifier][androguard.core.axml.ARSCResTableConfig.get_qualifier] instead.
        :returns: the qualifier string
        """
        return self.get_qualifier()

    def get_qualifier(self) -> str:
        """
        Return resource name qualifier for the current configuration.
        for example

        * `ldpi-v4`
        * `hdpi-v4`

        All possible qualifiers are listed in table 2 of <https://developer.android.com/guide/topics/resources/providing-resources>

        You can find how android process this at [ResourceTypes 3243](http://aospxref.com/android-13.0.0_r3/xref/frameworks/base/libs/androidfw/ResourceTypes.cpp#3243)

        :return: the resource name qualifer string
        """
        res = []

        mcc = self.imsi & 0xFFFF
        mnc = (self.imsi & 0xFFFF0000) >> 16
        if mcc != 0:
            res.append("mcc%d" % mcc)
        if mnc != 0:
            res.append("mnc%d" % mnc)

        if self.locale != 0:
            res.append(self.get_language_and_region())

        screenLayout = self.screenConfig & 0xFF
        if (screenLayout & MASK_LAYOUTDIR) != 0:
            if screenLayout & MASK_LAYOUTDIR == LAYOUTDIR_LTR:
                res.append("ldltr")
            elif screenLayout & MASK_LAYOUTDIR == LAYOUTDIR_RTL:
                res.append("ldrtl")
            else:
                res.append("layoutDir_%d" % (screenLayout & MASK_LAYOUTDIR))

        smallestScreenWidthDp = (self.screenConfig & 0xFFFF0000) >> 16
        if smallestScreenWidthDp != 0:
            res.append("sw%ddp" % smallestScreenWidthDp)

        screenWidthDp = self.screenSizeDp & 0xFFFF
        screenHeightDp = (self.screenSizeDp & 0xFFFF0000) >> 16
        if screenWidthDp != 0:
            res.append("w%ddp" % screenWidthDp)
        if screenHeightDp != 0:
            res.append("h%ddp" % screenHeightDp)

        if (screenLayout & MASK_SCREENSIZE) != SCREENSIZE_ANY:
            if screenLayout & MASK_SCREENSIZE == SCREENSIZE_SMALL:
                res.append("small")
            elif screenLayout & MASK_SCREENSIZE == SCREENSIZE_NORMAL:
                res.append("normal")
            elif screenLayout & MASK_SCREENSIZE == SCREENSIZE_LARGE:
                res.append("large")
            elif screenLayout & MASK_SCREENSIZE == SCREENSIZE_XLARGE:
                res.append("xlarge")
            else:
                res.append(
                    "screenLayoutSize_%d" % (screenLayout & MASK_SCREENSIZE)
                )
        if (screenLayout & MASK_SCREENLONG) != 0:
            if screenLayout & MASK_SCREENLONG == SCREENLONG_NO:
                res.append("notlong")
            elif screenLayout & MASK_SCREENLONG == SCREENLONG_YES:
                res.append("long")
            else:
                res.append(
                    "screenLayoutLong_%d" % (screenLayout & MASK_SCREENLONG)
                )

        screenLayout2 = self.screenConfig2 & 0xFF
        if (screenLayout2 & MASK_SCREENROUND) != 0:
            if screenLayout2 & MASK_SCREENROUND == SCREENROUND_NO:
                res.append("notround")
            elif screenLayout2 & MASK_SCREENROUND == SCREENROUND_YES:
                res.append("round")
            else:
                res.append(
                    "screenRound_%d" % (screenLayout2 & MASK_SCREENROUND)
                )

        colorMode = (self.screenConfig2 & 0xFF00) >> 8
        if (colorMode & MASK_WIDE_COLOR_GAMUT) != 0:
            if colorMode & MASK_WIDE_COLOR_GAMUT == WIDE_COLOR_GAMUT_NO:
                res.append("nowidecg")
            elif colorMode & MASK_WIDE_COLOR_GAMUT == WIDE_COLOR_GAMUT_YES:
                res.append("widecg")
            else:
                res.append(
                    "wideColorGamut_%d" % (colorMode & MASK_WIDE_COLOR_GAMUT)
                )

        if (colorMode & MASK_HDR) != 0:
            if colorMode & MASK_HDR == HDR_NO:
                res.append("lowdr")
            elif colorMode & MASK_HDR == HDR_YES:
                res.append("highdr")
            else:
                res.append("hdr_%d" % (colorMode & MASK_HDR))

        orientation = self.screenType & 0xFF
        if orientation != ORIENTATION_ANY:
            if orientation == ORIENTATION_PORT:
                res.append("port")
            elif orientation == ORIENTATION_LAND:
                res.append("land")
            elif orientation == ORIENTATION_SQUARE:
                res.append("square")
            else:
                res.append("orientation_%d" % orientation)

        uiMode = (self.screenConfig & 0xFF00) >> 8
        if (uiMode & MASK_UI_MODE_TYPE) != UI_MODE_TYPE_ANY:
            ui_mode = uiMode & MASK_UI_MODE_TYPE
            if ui_mode == UI_MODE_TYPE_DESK:
                res.append("desk")
            elif ui_mode == UI_MODE_TYPE_CAR:
                res.append("car")
            elif ui_mode == UI_MODE_TYPE_TELEVISION:
                res.append("television")
            elif ui_mode == UI_MODE_TYPE_APPLIANCE:
                res.append("appliance")
            elif ui_mode == UI_MODE_TYPE_WATCH:
                res.append("watch")
            elif ui_mode == UI_MODE_TYPE_VR_HEADSET:
                res.append("vrheadset")
            else:
                res.append("uiModeType_%d" % ui_mode)

        if (uiMode & MASK_UI_MODE_NIGHT) != 0:
            if uiMode & MASK_UI_MODE_NIGHT == UI_MODE_NIGHT_NO:
                res.append("notnight")
            elif uiMode & MASK_UI_MODE_NIGHT == UI_MODE_NIGHT_YES:
                res.append("night")
            else:
                res.append("uiModeNight_%d" % (uiMode & MASK_UI_MODE_NIGHT))

        density = (self.screenType & 0xFFFF0000) >> 16
        if density != DENSITY_DEFAULT:
            if density == DENSITY_LOW:
                res.append("ldpi")
            elif density == DENSITY_MEDIUM:
                res.append("mdpi")
            elif density == DENSITY_TV:
                res.append("tvdpi")
            elif density == DENSITY_HIGH:
                res.append("hdpi")
            elif density == DENSITY_XHIGH:
                res.append("xhdpi")
            elif density == DENSITY_XXHIGH:
                res.append("xxhdpi")
            elif density == DENSITY_XXXHIGH:
                res.append("xxxhdpi")
            elif density == DENSITY_NONE:
                res.append("nodpi")
            elif density == DENSITY_ANY:
                res.append("anydpi")
            else:
                res.append("%ddpi" % (density))

        touchscreen = (self.screenType & 0xFF00) >> 8
        if touchscreen != TOUCHSCREEN_ANY:
            if touchscreen == TOUCHSCREEN_NOTOUCH:
                res.append("notouch")
            elif touchscreen == TOUCHSCREEN_FINGER:
                res.append("finger")
            elif touchscreen == TOUCHSCREEN_STYLUS:
                res.append("stylus")
            else:
                res.append("touchscreen_%d" % touchscreen)

        keyboard = self.input & 0xFF
        navigation = (self.input & 0xFF00) >> 8
        inputFlags = (self.input & 0xFF0000) >> 16

        if inputFlags & MASK_KEYSHIDDEN != 0:
            input_flags = inputFlags & MASK_KEYSHIDDEN
            if input_flags == KEYSHIDDEN_NO:
                res.append("keysexposed")
            elif input_flags == KEYSHIDDEN_YES:
                res.append("keyshidden")
            elif input_flags == KEYSHIDDEN_SOFT:
                res.append("keyssoft")

        if keyboard != KEYBOARD_ANY:
            if keyboard == KEYBOARD_NOKEYS:
                res.append("nokeys")
            elif keyboard == KEYBOARD_QWERTY:
                res.append("qwerty")
            elif keyboard == KEYBOARD_12KEY:
                res.append("12key")
            else:
                res.append("keyboard_%d" % keyboard)

        if inputFlags & MASK_NAVHIDDEN != 0:
            input_flags = inputFlags & MASK_NAVHIDDEN
            if input_flags == NAVHIDDEN_NO:
                res.append("navexposed")
            elif input_flags == NAVHIDDEN_YES:
                res.append("navhidden")
            else:
                res.append("inputFlagsNavHidden_%d" % input_flags)

        if navigation != NAVIGATION_ANY:
            if navigation == NAVIGATION_NONAV:
                res.append("nonav")
            elif navigation == NAVIGATION_DPAD:
                res.append("dpad")
            elif navigation == NAVIGATION_TRACKBALL:
                res.append("trackball")
            elif navigation == NAVIGATION_WHEEL:
                res.append("wheel")
            else:
                res.append("navigation_%d" % navigation)

        screenSize = self.screenSize
        if screenSize != 0:
            screenWidth = self.screenSize & 0xFFFF
            screenHeight = (self.screenSize & 0xFFFF0000) >> 16
            res.append("%dx%d" % (screenWidth, screenHeight))

        version = self.version
        if version != 0:
            sdkVersion = self.version & 0xFFFF
            minorVersion = (self.version & 0xFFFF0000) >> 16
            res.append("v%d" % sdkVersion)
            if minorVersion != 0:
                res.append(".%d" % minorVersion)

        return "-".join(res)

    def get_language(self) -> str:
        x = self.locale & 0x0000FFFF
        return chr(x & 0x00FF) + chr((x & 0xFF00) >> 8)

    def get_country(self) -> str:
        x = (self.locale & 0xFFFF0000) >> 16
        return chr(x & 0x00FF) + chr((x & 0xFF00) >> 8)

    def get_density(self) -> str:
        x = (self.screenType >> 16) & 0xFFFF
        return x

    def is_default(self) -> bool:
        """
        Test if this is a default resource, which matches all

        This is indicated that all fields are zero.
        :returns: True if default, False otherwise
        """
        return all(map(lambda x: x == 0, self._get_tuple()))

    def _get_tuple(self):
        return (
            self.imsi,
            self.locale,
            self.screenType,
            self.input,
            self.screenSize,
            self.version,
            self.screenConfig,
            self.screenSizeDp,
            self.screenConfig2,
        )

    def __hash__(self):
        return hash(self._get_tuple())

    def __eq__(self, other):
        return self._get_tuple() == other._get_tuple()

    def __repr__(self):
        return "<ARSCResTableConfig '{}'={}>".format(
            self.get_qualifier(), repr(self._get_tuple())
        )


class _At:
    """A read-only stream over `raw` whose positions start at `start`."""

    __slots__ = ("_raw", "_start", "_pos")

    def __init__(self, start: int, raw: bytes) -> None:
        self._raw, self._start, self._pos = raw, start, 0

    def tell(self) -> int:
        return self._start + self._pos

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0:
            n = len(self._raw) - self._pos
        out = self._raw[self._pos:self._pos + n]
        self._pos += len(out)
        return out


def from_bytes(start: int, raw: bytes) -> ARSCResTableConfig:
    return ARSCResTableConfig(_At(start, raw))
