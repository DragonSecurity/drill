package version

const Version = "0.5.0"

var (
	UIVersion string
	GitCommit string
	BuildDate string
)

type BuildInfo struct {
	Version   string `json:"version"`
	UIVersion string `json:"ui_version"`
	GitCommit string `json:"git_commit"`
	BuildDate string `json:"build_date"`
}

func GetBuildInfo() BuildInfo {
	return BuildInfo{
		Version,
		UIVersion,
		GitCommit,
		BuildDate,
	}
}

func GenerateBuildVersionString() string {
	versionString := "Version     " + Version + "\n" +
		"UI version  " + UIVersion + "\n" +
		"Commit      " + GitCommit + "\n" +
		"Date        " + BuildDate

	return versionString
}
