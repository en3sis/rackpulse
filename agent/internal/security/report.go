package security

type Report struct {
	Version   string     `json:"version"`
	Time      int64      `json:"time"`
	OS        OSInfo     `json:"os"`
	Packages  Packages   `json:"packages"`
	Updates   Updates    `json:"updates"`
	Kernel    Kernel     `json:"kernel"`
	Checks    []Check    `json:"checks"`
	Listening []Listener `json:"listening"`
	Projects  []Project  `json:"projects"`
	Images    []Image    `json:"images"`
}

type OSInfo struct {
	ID        *string  `json:"id"`
	VersionID *string  `json:"versionID"`
	Codename  *string  `json:"codename"`
	Name      *string  `json:"name"`
	Like      []string `json:"like"`
}

type Packages struct {
	Manager *string   `json:"manager"`
	Time    int64     `json:"time"`
	Error   *string   `json:"error"`
	Items   []Package `json:"items"`
}

type Package struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	Source        string `json:"source"`
	SourceVersion string `json:"sourceVersion"`
	Arch          string `json:"arch"`
}

type Updates struct {
	Time      int64    `json:"time"`
	ListsTime *int64   `json:"listsTime"`
	Error     *string  `json:"error"`
	Items     []Update `json:"items"`
}

type Update struct {
	Name      string   `json:"name"`
	Current   *string  `json:"current"`
	Available string   `json:"available"`
	Security  bool     `json:"security"`
	Origins   []string `json:"origins"`
}

type Kernel struct {
	Running         *string `json:"running"`
	LatestInstalled *string `json:"latestInstalled"`
}

const (
	statusPass    = "pass"
	statusFail    = "fail"
	statusUnknown = "unknown"
)

type Check struct {
	ID     string  `json:"id"`
	Status string  `json:"status"`
	Title  string  `json:"title"`
	Detail string  `json:"detail"`
	Source *string `json:"source"`
}

type Listener struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
}

type Project struct {
	Name      string     `json:"name"`
	Path      string     `json:"path"`
	Error     *string    `json:"error"`
	Lockfiles []Lockfile `json:"lockfiles"`
}

type Lockfile struct {
	Path      string       `json:"path"`
	Ecosystem string       `json:"ecosystem"`
	Packages  []Dependency `json:"packages"`
	Truncated bool         `json:"truncated"`
}

type Image struct {
	ID         string     `json:"id"`
	Names      []string   `json:"names"`
	Containers []string   `json:"containers"`
	Created    *int64     `json:"created"`
	OS         OSInfo     `json:"os"`
	Packages   Packages   `json:"packages"`
	Lockfiles  []Lockfile `json:"lockfiles"`
	Error      *string    `json:"error"`
}

type Dependency struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func stringPointer(value string) *string {
	return &value
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
