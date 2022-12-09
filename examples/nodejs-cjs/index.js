const { Srp, Mode, Hash } = require("js-srp");

console.log(new Srp(Mode.SRPTools, Hash.SHA1, 1024));
