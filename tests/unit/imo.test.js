/**
 * IMO number validation — regression tests
 *
 * TODO: import validIMO and extractIMOs from app.js once extracted to a module.
 */

// import { validIMO, extractIMOs } from '../../lib/extract/imo.js';

describe('validIMO — check digit algorithm', () => {
  test.todo('accepts a known-valid IMO (e.g. 9074729)');
  test.todo('rejects a number with a wrong check digit');
  test.todo('rejects a 6-digit number');
  test.todo('rejects an 8-digit number');
  test.todo('rejects a non-numeric string');
  test.todo('rejects all-zeros');
});

describe('extractIMOs — free text scanning', () => {
  test.todo('finds IMO in "IMO: 9074729"');
  test.todo('finds IMO in "IMO#9074729"');
  test.todo('finds IMO in "IMO 9074729"');
  test.todo('finds IMO in "imo number 9074729"');
  test.todo('returns multiple IMOs when several appear in text');
  test.todo('does not return invalid IMOs that appear in text');
  test.todo('returns empty array when no IMO found');
});
