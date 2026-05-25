const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

let dbAdapter;

if (supabaseUrl && supabaseServiceKey) {
  console.log('=========================================');
  console.log(' DATABASE MODE: Supabase (Production)    ');
  console.log(' Connected to live cloud PostgreSQL      ');
  console.log('=========================================');
  dbAdapter = require('./dbSupabase');
} else {
  console.log('=========================================');
  console.log(' DATABASE MODE: Memory Mock (Local Dev)  ');
  console.log(' Note: Running without live Supabase database');
  console.log('=========================================');
  dbAdapter = require('./dbMock');
}

module.exports = dbAdapter;
