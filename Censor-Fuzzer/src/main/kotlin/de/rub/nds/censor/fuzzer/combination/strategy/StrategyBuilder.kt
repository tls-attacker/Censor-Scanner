package de.rub.nds.censor.fuzzer.combination.strategy

import de.rub.nds.censor.fuzzer.constants.Strategies

/**
 * Builds instantiated strategies from the [Strategies] enum.
 */
class StrategyBuilder(private val correctHostname: String, private val fillerHostname: String) {

    /**
     * Builds the default instantiation of the strategy
     */
    fun buildDefault(strategy: Strategies, sniEntryIndex: Int = 0): Strategy<*> {
        return when (strategy) {
            Strategies.EXTENSION -> ExtensionStrategy(correctHostname)
            Strategies.VERSION -> VersionStrategy()
            Strategies.RECORD_FRAGMENTATION -> RecordFragmentationStrategy()
            Strategies.RECORD_INJECTION -> RecordInjectionStrategy()
            Strategies.RECORD_VERSION -> RecordVersionStrategy()
            Strategies.RECORD_CONTENT_TYPE -> RecordContentTypeStrategy()
            Strategies.RECORD_LENGTH -> RecordLengthStrategy()
            Strategies.MESSAGE_TYPE -> MessageTypeStrategy()
            Strategies.MESSAGE_VERSION -> MessageVersionStrategy()
            Strategies.MESSAGE_LENGTH -> MessageLengthStrategy(correctHostname)
            Strategies.EXTENSIONS_LENGTH -> ExtensionsLengthStrategy(correctHostname)
            Strategies.PADDING -> PaddingStrategy()
            Strategies.ADDITIONAL_SNI -> AdditionalSniStrategy(fillerHostname)
            Strategies.MOVE_SNI -> MoveSniStrategy()
            Strategies.EXTENSION_TYPE -> ExtensionTypeStrategy()
            Strategies.LIST_LENGTH -> ListLengthStrategy(correctHostname)
            Strategies.EXTENSION_LENGTH -> ExtensionLengthStrategy(correctHostname)
            Strategies.CHANGE_CASE -> ChangeCaseStrategy(sniEntryIndex)
            Strategies.ASCII_PARITY_FLIP -> DecoderConfusionStrategy(sniEntryIndex)
            Strategies.NAME_LENGTH -> NameLengthStrategy(sniEntryIndex, correctHostname.length)
            Strategies.NAME_TYPE -> NameTypeStrategy(sniEntryIndex)
            Strategies.ADD_SUBDOMAIN -> AddSubdomainStrategy(sniEntryIndex)
            Strategies.INJECT_SYMBOL -> InjectSymbolStrategy(sniEntryIndex, correctHostname.length)
            Strategies.REPLACE_WITH_HARMLESS -> ReplaceWithHarmlessStrategy(sniEntryIndex)
            Strategies.PAD_TO_MAXIMUM -> PadToMaximumStrategy(sniEntryIndex)
            Strategies.ADDITIONAL_ENTRIES -> SniEntriesStrategy(
                originalHostname = correctHostname,
                harmlessHostname = fillerHostname
            )
        }
    }

    /**
     * Yields all instantiations of the strategy
     */
    fun buildAllInstantiations(strategy: Strategies, sniEntryIndex: Int = 0): List<Strategy<*>> {
        return when (strategy) {
            Strategies.EXTENSION -> ExtensionStrategy(correctHostname).instantiateWithAllPossibilities()
            Strategies.VERSION -> VersionStrategy().instantiateWithAllPossibilities()
            Strategies.RECORD_FRAGMENTATION -> RecordFragmentationStrategy().instantiateWithAllPossibilities()
            Strategies.RECORD_INJECTION -> RecordInjectionStrategy().instantiateWithAllPossibilities()
            Strategies.RECORD_VERSION -> RecordVersionStrategy().instantiateWithAllPossibilities()
            Strategies.RECORD_CONTENT_TYPE -> RecordContentTypeStrategy().instantiateWithAllPossibilities()
            Strategies.RECORD_LENGTH -> RecordLengthStrategy().instantiateWithAllPossibilities()
            Strategies.MESSAGE_TYPE -> MessageTypeStrategy().instantiateWithAllPossibilities()
            Strategies.MESSAGE_VERSION -> MessageVersionStrategy().instantiateWithAllPossibilities()
            Strategies.MESSAGE_LENGTH -> MessageLengthStrategy(correctHostname).instantiateWithAllPossibilities()
            Strategies.EXTENSIONS_LENGTH -> ExtensionsLengthStrategy(correctHostname).instantiateWithAllPossibilities()
            Strategies.PADDING -> PaddingStrategy().instantiateWithAllPossibilities()
            Strategies.ADDITIONAL_SNI -> AdditionalSniStrategy(fillerHostname).instantiateWithAllPossibilities()
            Strategies.MOVE_SNI -> MoveSniStrategy().instantiateWithAllPossibilities()
            Strategies.EXTENSION_TYPE -> ExtensionTypeStrategy().instantiateWithAllPossibilities()
            Strategies.LIST_LENGTH -> ListLengthStrategy(correctHostname).instantiateWithAllPossibilities()
            Strategies.EXTENSION_LENGTH -> ExtensionLengthStrategy(correctHostname).instantiateWithAllPossibilities()
            Strategies.CHANGE_CASE -> ChangeCaseStrategy(sniEntryIndex).instantiateWithAllPossibilities()
            Strategies.ASCII_PARITY_FLIP -> DecoderConfusionStrategy(sniEntryIndex).instantiateWithAllPossibilities()
            Strategies.NAME_LENGTH -> NameLengthStrategy(
                sniEntryIndex,
                correctHostname.length
            ).instantiateWithAllPossibilities()

            Strategies.NAME_TYPE -> NameTypeStrategy(sniEntryIndex).instantiateWithAllPossibilities()
            Strategies.ADD_SUBDOMAIN -> AddSubdomainStrategy(sniEntryIndex).instantiateWithAllPossibilities()
            Strategies.INJECT_SYMBOL -> InjectSymbolStrategy(
                sniEntryIndex,
                correctHostname.length
            ).instantiateWithAllPossibilities()

            Strategies.REPLACE_WITH_HARMLESS -> ReplaceWithHarmlessStrategy(sniEntryIndex).instantiateWithAllPossibilities()
            Strategies.PAD_TO_MAXIMUM -> PadToMaximumStrategy(sniEntryIndex).instantiateWithAllPossibilities()
            Strategies.ADDITIONAL_ENTRIES -> SniEntriesStrategy(
                originalHostname = correctHostname,
                harmlessHostname = fillerHostname
            ).instantiateWithAllPossibilities()
        }
    }

    /**
     * Yields all instantiations of the strategy except the default configuration
     */
    fun buildAllInstantiationsExceptDefault(strategy: Strategies, sniEntryIndex: Int = 0): List<Strategy<*>> {
        return when (strategy) {
            Strategies.EXTENSION -> ExtensionStrategy(correctHostname).instantiateWithAllPossibilitiesExceptDefault()
            Strategies.VERSION -> VersionStrategy().instantiateWithAllPossibilitiesExceptDefault()
            Strategies.RECORD_FRAGMENTATION -> RecordFragmentationStrategy().instantiateWithAllPossibilitiesExceptDefault()
            Strategies.RECORD_INJECTION -> RecordInjectionStrategy().instantiateWithAllPossibilitiesExceptDefault()
            Strategies.RECORD_VERSION -> RecordVersionStrategy().instantiateWithAllPossibilitiesExceptDefault()
            Strategies.RECORD_CONTENT_TYPE -> RecordContentTypeStrategy().instantiateWithAllPossibilitiesExceptDefault()
            Strategies.RECORD_LENGTH -> RecordLengthStrategy().instantiateWithAllPossibilitiesExceptDefault()
            Strategies.MESSAGE_TYPE -> MessageTypeStrategy().instantiateWithAllPossibilitiesExceptDefault()
            Strategies.MESSAGE_VERSION -> MessageVersionStrategy().instantiateWithAllPossibilitiesExceptDefault()
            Strategies.MESSAGE_LENGTH -> MessageLengthStrategy(correctHostname).instantiateWithAllPossibilitiesExceptDefault()
            Strategies.EXTENSIONS_LENGTH -> ExtensionsLengthStrategy(correctHostname).instantiateWithAllPossibilitiesExceptDefault()
            Strategies.PADDING -> PaddingStrategy().instantiateWithAllPossibilitiesExceptDefault()
            Strategies.ADDITIONAL_SNI -> AdditionalSniStrategy(fillerHostname).instantiateWithAllPossibilitiesExceptDefault()
            Strategies.MOVE_SNI -> MoveSniStrategy().instantiateWithAllPossibilitiesExceptDefault()
            Strategies.EXTENSION_TYPE -> ExtensionTypeStrategy().instantiateWithAllPossibilitiesExceptDefault()
            Strategies.LIST_LENGTH -> ListLengthStrategy(correctHostname).instantiateWithAllPossibilitiesExceptDefault()
            Strategies.EXTENSION_LENGTH -> ExtensionLengthStrategy(correctHostname).instantiateWithAllPossibilitiesExceptDefault()
            Strategies.CHANGE_CASE -> ChangeCaseStrategy(sniEntryIndex).instantiateWithAllPossibilitiesExceptDefault()
            Strategies.ASCII_PARITY_FLIP -> DecoderConfusionStrategy(sniEntryIndex).instantiateWithAllPossibilitiesExceptDefault()
            Strategies.NAME_LENGTH -> NameLengthStrategy(
                sniEntryIndex,
                correctHostname.length
            ).instantiateWithAllPossibilitiesExceptDefault()

            Strategies.NAME_TYPE -> NameTypeStrategy(sniEntryIndex).instantiateWithAllPossibilitiesExceptDefault()
            Strategies.ADD_SUBDOMAIN -> AddSubdomainStrategy(sniEntryIndex).instantiateWithAllPossibilitiesExceptDefault()
            Strategies.INJECT_SYMBOL -> InjectSymbolStrategy(
                sniEntryIndex,
                correctHostname.length
            ).instantiateWithAllPossibilitiesExceptDefault()

            Strategies.REPLACE_WITH_HARMLESS -> ReplaceWithHarmlessStrategy(sniEntryIndex).instantiateWithAllPossibilitiesExceptDefault()
            Strategies.PAD_TO_MAXIMUM -> PadToMaximumStrategy(sniEntryIndex).instantiateWithAllPossibilitiesExceptDefault()
            Strategies.ADDITIONAL_ENTRIES -> SniEntriesStrategy(
                originalHostname = correctHostname,
                harmlessHostname = fillerHostname
            ).instantiateWithAllPossibilitiesExceptDefault()
        }
    }
}