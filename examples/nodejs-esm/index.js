import { Srp, Mode, Hash } from "js-srp";

console.log(new Srp(Mode.SRPTools, Hash.SHA1, 1024));
