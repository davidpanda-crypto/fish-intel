/**
 * extractFields() — regression tests against fixture HTML
 *
 * TODO: import extractFields once extracted to a module.
 * Fixtures live in tests/fixtures/html/
 */

// import { extractFields } from '../../lib/extract/fields.js';
// import { readFileSync } from 'fs';

describe('extractFields — table parsing', () => {
  test.todo('extracts fields from a 2-column label/value table');
  test.todo('extracts fields from a 4-column label/value/label/value table');
  test.todo('maps "Flag State" label → flag field');
  test.todo('maps "Gross Tonnage" label → gross_tonnage field');
  test.todo('maps "Year Built" label → year_built field');
});

describe('extractFields — JSON-LD', () => {
  test.todo('extracts name from JSON-LD');
  test.todo('extracts geo.latitude / geo.longitude from GeoCoordinates');
  test.todo('extracts address.addressCountry from PostalAddress');
  test.todo('handles JSON-LD arrays (multiple items in one script block)');
});

describe('extractFields — coordinate sources', () => {
  test.todo('extracts lat/lon from Google Maps iframe src');
  test.todo('extracts lat/lon from Google Maps anchor href');
  test.todo('extracts lat/lon from data-lat / data-lng attributes');
  test.todo('extracts lat/lon from Schema.org itemprop="latitude"');
  test.todo('extracts lat/lon from Leaflet setView([lat, lon]) in page script');
  test.todo('extracts lat/lon from JSON-format {"lat": 60.12, "lng": 5.34}');
  test.todo('converts DMS format (60°12\'34"N 005°19\'22"E) to decimal');
});

describe('extractFields — noise rejection', () => {
  test.todo('does not save "N/A" as a field value');
  test.todo('does not save "Unknown" as a field value');
  test.todo('does not save "Login" as a field value');
  test.todo('does not save "Read more" as a field value');
  test.todo('does not save a URL string as a description');
  test.todo('does not save a copyright notice as a description');
});

describe('extractFields — MarineTraffic fixture', () => {
  test.todo('extracts vessel_name from fixture');
  test.todo('extracts imo from fixture');
  test.todo('extracts flag from fixture');
  test.todo('extracts gross_tonnage from fixture');
  test.todo('extracts year_built from fixture');
});

describe('extractFields — ASC farm fixture', () => {
  test.todo('extracts farm_name from fixture');
  test.todo('extracts country from fixture');
  test.todo('extracts species from fixture');
  test.todo('extracts certification = "ASC Certified" from fixture');
});
