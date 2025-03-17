package de.rub.nds.censor.fuzzer.combination.instantiation

enum class InjectSymbolInstantiation : Instantiation {
    NONE,
    BEFORE_00,
    MIDDLE_00,
    AFTER_00,
    BEFORE_SPACE,
    MIDDLE_SPACE,
    AFTER_SPACE,
    BEFORE_BACKSPACE,
    MIDDLE_BACKSPACE,
    AFTER_BACKSPACE,
    BEFORE_LEFT_TO_RIGHT_UNICODE,
    MIDDLE_LEFT_TO_RIGHT_UNICODE,
    AFTER_LEFT_TO_RIGHT_UNICODE,
    AFTER_INCOMPLETE_UNICODE
}