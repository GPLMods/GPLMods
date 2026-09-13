AdminJS.UserComponents = {}
AdminJS.env.NODE_ENV = "production"
import Dashboard from '../components/dashboard/CustomDashboard'
AdminJS.UserComponents.Dashboard = Dashboard
import SidebarBranding from '../components/dashboard/SidebarBranding'
AdminJS.UserComponents.SidebarBranding = SidebarBranding
import ActionRedirect from '../components/actions/ActionRedirect'
AdminJS.UserComponents.ActionRedirect = ActionRedirect
import VariantBadge from '../components/cells/VariantBadge'
AdminJS.UserComponents.VariantBadge = VariantBadge
import AvatarCell from '../components/cells/AvatarCell'
AdminJS.UserComponents.AvatarCell = AvatarCell
import ImagePreview from '../components/cells/ImagePreview'
AdminJS.UserComponents.ImagePreview = ImagePreview
import ManageVotes from '../components/actions/ManageVotes'
AdminJS.UserComponents.ManageVotes = ManageVotes