"""
Class for software with CPE
(https://nvd.nist.gov/products/cpe)
"""

from CPE import CPE


class SoftwareWithCPE:
    """
    Class for software with CPE
    (https://nvd.nist.gov/products/cpe)
    """
    software_name: str
    cpe: CPE

    def __init__(self, software_name: str = None, software_version: str = None, cpe_name: CPE = None) -> None:
        """
        Class Initialization Function. Gets called when the object is created

        Parameters
        ----------
        software_name (str) : The name of the installed software
        software_version (str) : The version of the installed software
        cpe_name (CPE) : The name of the CPE

        Raises
        ------
        ValueError
                If the value of software_name, cpe_name is None

        """
        if software_name is None and software_version is None and cpe_name is None:
            raise ValueError(
                "software_name, software_version, cpe_name cannot be None")

        self.software_name = software_name
        
        self.cpe = CPE(cpe_name)
        self.cpe.version = software_version
        
    
    def __dict__(self) -> dict:
        """
        Dictionary format of the class

        Returns
        -------
        dict : The object in its JSON format

        """
        return {
            "software_name": self.software_name,
            "cpe_name": self.cpe.assemble_cpe(),
            "cpe_version": self.cpe.cpe_version
        }
