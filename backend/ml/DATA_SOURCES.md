# ScamSathi detection data provenance

## Data currently used

`dataset_fixture.csv` is an internal 24-row development fixture (12 `scam`, 12 `benign`). It has no per-row source, consent, license, language, category, or collection-date fields. The rows are largely English; a few are Romanized Hindi. It is not a representative fraud corpus. Do not use its metrics to claim production or multilingual performance.

No external data was downloaded or merged into the repository in this change. This avoids importing text whose collection consent, privacy restrictions, or redistribution terms have not been checked at the actual download source.

## Candidate sources reviewed

| Source | What it may contribute | Provenance / license caveat | Use decision |
| --- | --- | --- | --- |
| [UCI SMS Spam Collection, DOI 10.24432/C5CC84](https://archive.ics.uci.edu/dataset/228/sms%2Bspam%2Bcollection) | 5,574 English ham/spam SMS; useful English baseline and benign short-message coverage | UCI lists CC BY 4.0 and describes mixed origins (public spam reports, volunteer NUS ham, thesis examples, and another spam corpus). Attribute UCI and preserve component provenance. Labels target general SMS spam, not specifically Indian fraud. | Suitable for an attributed English baseline after provenance-aware deduplication; not multilingual coverage. |
| [Spam SMS in Hindi Language, IEEE DataPort DOI 10.21227/5y8x-n678](https://dx.doi.org/10.21227/5y8x-n678) | A research dataset described by its authors’ institution as 3,894 Hindi spam/ham messages collected from students’ experience and shared messages | The university dataset page describes privacy handling and labels, but this audit could not verify the downloadable record’s redistribution license or detailed consent terms. | Candidate only; review IEEE DataPort terms and consent/provenance before use. |
| [Spam SMS in Dravidian Languages, IEEE DataPort DOI 10.21227/dcym-pd69](https://dx.doi.org/10.21227/dcym-pd69) | Tamil, Telugu, Kannada, Malayalam, English and Tamil Romanization; authors describe roughly 7,700 spam/ham examples collected via contacts and language-expert labeling | The authors’ page describes collection and labeling; license and exact per-language counts were not verifiable from the accessible landing page during this audit. “Spam” also includes promotional/annoying messages, not only fraud. | Candidate only; verify license, consent, labels, and per-language split before use. |
| [Multilingual SMS spam survey and dataset review](https://pmc.ncbi.nlm.nih.gov/articles/PMC11891295/) | Secondary source for discovering Hindi-transliterated and Bengali SMS corpora | A review is not itself a data license or permission to redistribute underlying messages. | Discovery aid only; inspect the primary dataset source before use. |

Machine-translated corpora can be useful augmentation, but translated messages are not independent observed fraud examples. Keep their source message IDs and translation provenance grouped in the same split as the original, and report augmented-language metrics separately from native-language results.

## Required columns before an import

Keep a private, access-controlled source file with at least: `text`, normalized `label`, `source_dataset`, `source_record_id`, `source_url_or_doi`, `license`, `consent_basis`, `original_label`, `language`, `script`, `category`, `is_translated_or_synthetic`, `translation_parent_id`, and `collection_date` when known. Strip personal data before import. The trainer should fail on contradictory duplicate labels and group near duplicates before splitting.
