package c2blue55

// versionModule est la version du module, sous la forme majeur.mineur.correctif.
// Les README (README.md et README.fr.md) portent une section datée par version ;
// le test de contrat TestReadmeV83Contrat vérifie qu'ils décrivent celle-ci.
const versionModule = "8.3.0"

// VersionModule rend la version du module c2blue55, sous la forme
// majeur.mineur.correctif, sans préfixe.
func VersionModule() string {
	return versionModule
}
