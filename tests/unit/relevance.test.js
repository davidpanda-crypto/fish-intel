/**
 * relevanceScore() and topicMatch() — regression tests
 *
 * These guard against cross-category contamination (e.g. vessel pages
 * appearing in farm searches) and off-domain pages (hotels, restaurants).
 */

// import { relevanceScore, topicMatch, isSeaRelated } from '../../lib/extract/fields.js';

describe('isSeaRelated — domain gate', () => {
  test.todo('returns true for text containing "aquaculture"');
  test.todo('returns true for text containing "trawler"');
  test.todo('returns true for text containing "IMO"');
  test.todo('returns false for a hotel description');
  test.todo('returns false for a restaurant menu');
  test.todo('returns false for empty string');
});

describe('topicMatch — cross-category exclusion', () => {
  test.todo('farm search: accepts a page with farm keywords');
  test.todo('farm search: rejects a page with only vessel keywords (no farm keywords)');
  test.todo('vessel search: accepts a page with vessel keywords');
  test.todo('vessel search: rejects a page with only farm keywords');
  test.todo('mill search: accepts a page with fishmeal/fish oil keywords');
  test.todo('general search: accepts any sea-related page');
  test.todo('any type: rejects a page that fails isSeaRelated');
});

describe('relevanceScore', () => {
  test.todo('returns 0 for text with no query terms');
  test.todo('returns count of term occurrences');
  test.todo('ignores terms shorter than 3 characters');
  test.todo('is case-insensitive');
});
