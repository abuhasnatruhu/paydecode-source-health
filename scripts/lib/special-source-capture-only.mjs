// Fixed artifact-only scope from the existing October11 PG/NE legal-watch contract.
// No user-supplied URL, new source family or source SHA is accepted.
export const SOURCE_SHA='a013cf5e55985ece73d6720c1fc76ff9f9d18d72';
export const RUNNER_REPOSITORY='abuhasnatruhu/paydecode-source-health';
export const WORKFLOW_PATH='.github/workflows/special-source-capture-only.yml';
export const USER_AGENT='PayDecode source maintenance (contact: hello@paydecode.com)';
export const MAX_BYTES=2*1024*1024;
export const SPECIAL_SOURCES=Object.freeze([
  Object.freeze({id:'pg-cb-088',kind:'pdf',url:'https://mgaleg.maryland.gov/pubs/LegisLegal/County-Legislation/2025-Prince-Georges-County-CB-088-2024.pdf'}),
  Object.freeze({id:'ne-archive',kind:'html',url:'https://ago.nebraska.gov/archived-news'}),
  Object.freeze({id:'ne-lincoln',kind:'html',url:'https://ago.nebraska.gov/lancaster-county-district-court-prohibits-city-lincoln-enforcing-unconstitutional-minimum-wage'}),
  Object.freeze({id:'ne-omaha',kind:'html',url:'https://ago.nebraska.gov/news/attorney-general-hilgers-sues-city-omaha-over-unconstitutional-minimum-wage-ordinance'}),
]);
export const getSpecialCaptureSource=id=>SPECIAL_SOURCES.find(source=>source.id===id);
