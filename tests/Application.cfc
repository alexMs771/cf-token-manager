component {

	this.name = "CFTokenManagerTestSuite";

	this.testsRoot = getDirectoryFromPath( getCurrentTemplatePath() );
	this.packageRoot = reReplaceNoCase( this.testsRoot, "tests[/\\\\]$", "" );

	this.mappings[ "/cftokenmanager" ] = this.packageRoot;
	this.mappings[ "/tests" ] = this.testsRoot;

}
