"""
CPE name class
"""


class CPE:
    """
    CPE name class
    """
    cpe: str
    cpe_version: str
    part: str
    vendor: str
    product: str
    version: str = '*'
    update: str = '*'
    edition: str = '*'
    language: str = '*'
    sw_edition: str = '*'
    target_sw: str = '*'
    target_hw: str = '*'
    other: str = '*'

    def __init__(self, cpe_string: str = None) -> None:
        """
        Class Initialization Function. Gets called when the object is created

        Parameters
        ----------
        cpe_string (str) : CPE string

        Raises
        ------
        ValueError
            If the value of cpe_string is None

        """
        if cpe_string is None:
            raise ValueError("cpe_string cannot be None")

        cpe_components = cpe_string.split(':')
        try:
            self.cpe = cpe_components[0]
            self.cpe_version = cpe_components[1]
            self.part = cpe_components[2]
            self.vendor = cpe_components[3]
            self.product = cpe_components[4]
            self.version = cpe_components[5]
            self.update = cpe_components[6] 
            self.edition = cpe_components[7] 
            self.language = cpe_components[8] 
            self.sw_edition = cpe_components[9] 
            self.target_sw = cpe_components[10] 
            self.target_hw = cpe_components[11] 
            self.other = cpe_components[12] 
        except IndexError:
            pass

    def assemble_cpe(self):
        return ":".join([
            self.cpe,
            self.cpe_version,
            self.part, 
            self.vendor, 
            self.product, 
            self.version, 
            self.update, 
            self.edition, 
            self.language, 
            self.sw_edition, 
            self.target_sw, 
            self.target_hw, 
            self.other
            ])
