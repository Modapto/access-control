package gr.atc.modapto.enums;

/*
* Enum for Pilot Codes
 */
public enum PilotCode {
    CRF("CRF"),
    ILTAR("ILTAR"),
    SEW("SEW"),
    FFT("FFT"),
    NONE("NONE");

    private final String pilot;

    PilotCode(final String pilot) {
        this.pilot = pilot;
    }

    @Override
    public String toString() {
        return pilot;
    }
}
