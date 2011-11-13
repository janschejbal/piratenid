<!--<![endif]-->  <!-- end block IE 6 -->
</div> <!-- end main content -->
<div id="footer">
	<a href="/">PiratenID</a> ist ein Dienst der <a href="http://www.piratenpartei.de/">Piratenpartei Deutschland</a> (<a href="http://www.piratenpartei.de/impressum">Impressum</a>),
	betrieben von der <a href="http://wiki.piratenpartei.de/IT">BundesIT</a>.
</div>
</div> <!-- end container -->
<div id="clickjackingwarning">
	Aus Sicherheitsgründen (Schutz vor Clickjacking) kann das Piraten-ID-System nicht in Frames oder iFrames eingebunden werden werden.
</div>

<script>
	if (window!=window.top) {
		document.getElementById('container').style.display = 'none';
		alert("ACHTUNG: Jemand hat versucht, das Piraten-ID-System in einem (i)frame einzubinden. Bitte mit Angabe der Website an die IT der Piratenpartei melden!");
	} else {
		document.getElementById('clickjackingwarning').style.display = 'none';
	}
</script>


</body>
</html>