import {loadBundle,validateBundle,buildPlan} from './lib.mjs';
const command=process.argv[2];
if(!['check','plan'].includes(command)){console.error('Only offline commands are supported: check | plan');process.exitCode=2;}
else {try {const b=await loadBundle();console.log(JSON.stringify(command==='check'?validateBundle(b):buildPlan(b),null,2));}catch(e){console.error(e.message);process.exitCode=1;}}
