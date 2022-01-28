<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
	version="1.0"
	xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
	xmlns="http://www.w3.org/1999/html">

	<xsl:output method="text" indent="no" encoding="UTF-8"/>

	<xsl:template match="/nmaprun">

		<!-- Headings -->
		<xsl:text>"Address",</xsl:text>
		<xsl:text>"Hostname",</xsl:text>
		<xsl:text>"RecType",</xsl:text>
		<xsl:text>"State",</xsl:text>
		<xsl:text>"Proto",</xsl:text>
		<xsl:text>"Port",</xsl:text>
		<xsl:text>"Service",</xsl:text>
		<xsl:text>"State",</xsl:text>
		<xsl:text>"Product",</xsl:text>
		<xsl:text>"OS Match",</xsl:text>
		<xsl:text>"OS Type/Vendor/Family/Gen"</xsl:text>
		<xsl:text>&#10;</xsl:text>

		<!-- Ports -->
		<xsl:for-each select="host/ports/port">
			<xsl:text>"</xsl:text>
			<xsl:value-of select="../../address/@addr"/>
			<xsl:text>","</xsl:text>
			<xsl:value-of select="../../hostnames/hostname/@name"/>
			<xsl:text>","</xsl:text>
			<xsl:value-of select="../../hostnames/hostname/@type"/>
			<xsl:text>","</xsl:text>
			<xsl:value-of select="../../status/@state"/>
			<xsl:text>","</xsl:text>
			<xsl:value-of select="@protocol"/>
			<xsl:text>","</xsl:text>
			<xsl:value-of select="@portid"/>
			<xsl:text>","</xsl:text>
			<xsl:value-of select="service/@name"/>
			<xsl:text>","</xsl:text>
			<xsl:value-of select="state/@state"/>
			<xsl:text>","</xsl:text>
			<xsl:value-of select="service/@product"/>
			<xsl:text>","</xsl:text>
			<xsl:value-of select="../../os/osmatch/@name"/>
			<xsl:text>","</xsl:text>
			<xsl:value-of select="../../os/osmatch/osclass/@type"/>
			<xsl:text> / </xsl:text>
			<xsl:value-of select="../../os/osmatch/osclass/@vendor"/>
			<xsl:text> / </xsl:text>
			<xsl:value-of select="../../os/osmatch/osclass/@osfamily"/>
			<xsl:text> / </xsl:text>
			<xsl:value-of select="../../os/osmatch/osclass/@osgen"/>
			<xsl:text>"</xsl:text>
			<xsl:text>&#10;</xsl:text>
		</xsl:for-each>

	</xsl:template>

</xsl:stylesheet>
