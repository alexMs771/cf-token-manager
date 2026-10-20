<cfsetting requesttimeout="999999">
<cfscript>
	param name="url.reporter" default="simple";
	param name="url.directory" default="tests.specs";
	param name="url.recurse" default="true" type="boolean";

	writeOutput(
		new testbox.system.TestBox(
			directory = url.directory,
			recurse   = url.recurse
		).run( reporter = url.reporter )
	);
</cfscript>
